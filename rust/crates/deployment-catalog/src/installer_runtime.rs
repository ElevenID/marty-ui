//! Bounded Linux subprocess execution and read-only Docker preflight.
//! No Docker resource is created by preflight. The caller owns all mutation
//! arguments and must persist resource ownership before using run_checked.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{ErrorKind, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub type Result<T> = std::result::Result<T, String>;
const MAX_OUTPUT: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

fn trusted_ancestors(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent).map_err(|_| "runtime ancestor unavailable")?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err("unsafe runtime path ancestor".into());
        }
    }
    Ok(())
}
fn executable(path: &Path) -> Result<()> {
    trusted_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "Docker executable unavailable")?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || fs::canonicalize(path).map_err(|_| "Docker executable unavailable")? != path
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
    {
        return Err("Docker executable must be an absolute trusted ordinary executable".into());
    }
    Ok(())
}
pub(crate) fn private_parent(path: &Path) -> Result<()> {
    trusted_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "private runtime parent unavailable")?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || fs::canonicalize(path).map_err(|_| "private runtime parent unavailable")? != path
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("runtime staging parent must be an owned private directory".into());
    }
    Ok(())
}
fn endpoint(host: &str) -> Result<()> {
    let path = host
        .strip_prefix("unix://")
        .ok_or("a local Docker Unix socket is required")?;
    if path.contains(['\0', '\r', '\n'])
        || !Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("invalid local Docker endpoint".into());
    }
    Ok(())
}
fn engine_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b))
}

struct OwnedChild {
    child: Child,
    reaped: bool,
}
impl OwnedChild {
    fn kill_group(&self) {
        // The leader is never reaped until cleanup. Its PID cannot be reused,
        // so this targets only the process group created for our own command.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
    }
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // WNOWAIT observes termination without reaping/releasing the PID.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err("runtime process observation failed".into());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<()> {
        self.kill_group();
        let status = self
            .child
            .wait()
            .map_err(|_| "runtime process wait failed")?;
        self.reaped = true;
        if !status.success() {
            return Err("Docker command failed; inspect owned runtime separately".into());
        }
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_group();
            let _ = self.child.wait();
        }
    }
}
fn nonblocking(stream: &impl AsRawFd) -> Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("runtime pipe configuration failed".into());
    }
    Ok(())
}
fn drain(stream: &mut impl Read, output: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut buffer = [0u8; 8192];
    // Bound work per poll so continuous output cannot starve the deadline.
    for _ in 0..32 {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(size) => {
                if output.len().saturating_add(size) > limit {
                    return Err("Docker command output exceeds limit".into());
                }
                output.extend_from_slice(&buffer[..size]);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err("runtime pipe read failed".into()),
        }
    }
    Ok(false)
}

struct BoundedRunner {
    executable: PathBuf,
    staging: tempfile::TempDir,
    docker_host: Option<String>,
}
impl BoundedRunner {
    fn new(binary: &Path, host: &str, parent: &Path) -> Result<Self> {
        executable(binary)?;
        endpoint(host)?;
        private_parent(parent)?;
        let staging = tempfile::Builder::new()
            .prefix(".installer-command-")
            .tempdir_in(parent)
            .map_err(|_| "cannot create isolated runtime configuration")?;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect isolated runtime configuration")?;
        Ok(Self {
            executable: binary.to_path_buf(),
            staging,
            docker_host: Some(host.into()),
        })
    }
    fn run(&self, args: &[&str], timeout: Duration, limit: usize) -> Result<String> {
        executable(&self.executable)?;
        private_parent(self.staging.path())?;
        if args.len() > 256 || args.iter().any(|a| a.len() > 16384 || a.contains('\0')) {
            return Err("runtime arguments exceed bounds".into());
        }
        let mut command = Command::new(&self.executable);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.staging.path())
            .env("DOCKER_CONFIG", self.staging.path())
            .env("XDG_CONFIG_HOME", self.staging.path())
            .env("XDG_CACHE_HOME", self.staging.path())
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir(self.staging.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(host) = &self.docker_host {
            command.env("DOCKER_HOST", host);
        } else {
            command
                .env("GH_CONFIG_DIR", self.staging.path())
                .env("GH_HOST", "github.com")
                .env("GH_PROMPT_DISABLED", "1");
        }
        let child = command.spawn().map_err(|_| "cannot start Docker command")?;
        let mut owned = OwnedChild {
            child,
            reaped: false,
        };
        let mut stdout = owned
            .child
            .stdout
            .take()
            .ok_or("runtime stdout unavailable")?;
        let mut stderr = owned
            .child
            .stderr
            .take()
            .ok_or("runtime stderr unavailable")?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let started = Instant::now();
        let mut output = Vec::new();
        let mut diagnostic = Vec::new();
        loop {
            if started.elapsed() >= timeout {
                return Err(
                    "Docker command timed out; owned child process group was cancelled".into(),
                );
            }
            let out_done = drain(&mut stdout, &mut output, limit)?;
            let err_done = drain(&mut stderr, &mut diagnostic, limit)?;
            if owned.exited()? {
                // A CLI that exits while a helper retains a pipe must not leave
                // a background helper or make us wait forever for pipe closure.
                owned.kill_group();
                if out_done && err_done {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        owned.finish()?;
        String::from_utf8(output).map_err(|_| "Docker command returned non-UTF8 output".into())
    }
}

/// Invoke an already hash-pinned installer verifier with bounded execution and
/// no inherited credentials/configuration. Only reviewed internal callers may
/// construct arguments; caller authenticates binary and private input bytes.
pub(crate) fn run_installer_verifier(
    binary: &Path,
    args: &[&str],
    parent: &Path,
) -> Result<String> {
    let mut runner = BoundedRunner::new(binary, "unix:///var/run/docker.sock", parent)?;
    runner.docker_host = None;
    runner.run(args, Duration::from_secs(120), 4 * 1024 * 1024)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerInfo {
    id: String,
    os: String,
    architecture: String,
    server_version: String,
    security_options: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct DockerObservation {
    pub engine_id: String,
    pub os: String,
    pub architecture: String,
    pub server_version: String,
    pub compose_version: String,
}
fn validate_info(output: &str, expected: &str) -> Result<DockerInfo> {
    let info: DockerInfo =
        serde_json::from_str(output).map_err(|_| "Docker info response is invalid")?;
    if info.id != expected
        || !engine_id(&info.id)
        || info.os != "linux"
        || !matches!(info.architecture.as_str(), "amd64" | "x86_64")
        || info.security_options.iter().any(|v| {
            ["name=rootless", "name=userns"]
                .iter()
                .any(|name| v == name || v.starts_with(&format!("{name},")))
        })
        || info.server_version.is_empty()
        || info.server_version.len() > 128
    {
        return Err("Docker Engine identity, platform, or rootful policy differs".into());
    }
    Ok(info)
}

pub struct DockerRunner {
    runner: BoundedRunner,
    expected_engine_id: String,
}
impl DockerRunner {
    pub fn new(
        docker_executable: &Path,
        docker_host: &str,
        expected_engine_id: &str,
        private_parent: &Path,
    ) -> Result<Self> {
        if !engine_id(expected_engine_id) {
            return Err("invalid expected Docker Engine identity".into());
        }
        Ok(Self {
            runner: BoundedRunner::new(docker_executable, docker_host, private_parent)?,
            expected_engine_id: expected_engine_id.into(),
        })
    }
    fn info(&self) -> Result<DockerInfo> {
        let output = self.runner.run(&["info", "--format", "{\"id\":{{json .ID}},\"os\":{{json .OSType}},\"architecture\":{{json .Architecture}},\"server_version\":{{json .ServerVersion}},\"security_options\":{{json .SecurityOptions}}}"], Duration::from_secs(30), 65536)?;
        validate_info(&output, &self.expected_engine_id)
    }
    /// Read-only Docker checks, using the isolated configuration and fixed socket.
    pub fn preflight(&self) -> Result<DockerObservation> {
        let info = self.info()?;
        let compose_version = self
            .runner
            .run(
                &["compose", "version", "--short"],
                Duration::from_secs(30),
                1024,
            )?
            .trim()
            .to_owned();
        if !regex::Regex::new(r"\Av?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\z")
            .unwrap()
            .is_match(&compose_version)
        {
            return Err("Docker Compose plugin version unavailable".into());
        }
        Ok(DockerObservation {
            engine_id: info.id,
            os: info.os,
            architecture: info.architecture,
            server_version: info.server_version,
            compose_version,
        })
    }
    /// For reviewed orchestration only. Checks identity immediately before each
    /// command; caller must additionally validate resource IDs, mounts and labels.
    /// A daemon replaced after inspection remains a runtime race: inspect every
    /// created resource before recording success, rather than treating this as a
    /// transaction with Docker. No user-controlled global CLI options are allowed.
    pub fn run_checked(&self, args: &[&str]) -> Result<String> {
        self.run_checked_with_timeout(args, COMMAND_TIMEOUT)
    }
    /// Internal stage-specific budgets remain finite; never inherit a user's
    /// timeout or let image downloads remove the subprocess cancellation bound.
    pub(crate) fn run_checked_with_timeout(
        &self,
        args: &[&str],
        timeout: Duration,
    ) -> Result<String> {
        if timeout.is_zero() || timeout > Duration::from_secs(900) {
            return Err("invalid Docker operation timeout".into());
        }
        if !matches!(
            args.first(),
            Some(
                &"compose"
                    | &"inspect"
                    | &"ps"
                    | &"network"
                    | &"volume"
                    | &"image"
                    | &"pull"
                    | &"run"
                    | &"create"
                    | &"start"
                    | &"wait"
                    | &"rm"
            )
        ) || args.iter().any(|arg| {
            ["--host", "--context", "--config", "--tls", "--tlsverify"]
                .iter()
                .any(|key| *arg == *key || arg.starts_with(&format!("{key}=")))
                || arg.starts_with("-H")
                || arg.starts_with("-c")
        }) {
            return Err("unapproved Docker command or endpoint override".into());
        }
        self.info()?;
        self.runner.run(args, timeout, MAX_OUTPUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private_temp() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn script(parent: &Path, body: &str) -> PathBuf {
        let path = parent.join("docker-stub");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn info() -> &'static str {
        r#"{"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=seccomp,profile=builtin"]}"#
    }
    #[test]
    fn refuses_replaceable_executable_and_private_staging_ancestors() {
        let root = private_temp();
        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let binary = script(&shared, "exit 0");
        assert!(executable(&binary).is_err());
        let private = shared.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_parent(&private).is_err());
    }
    #[test]
    fn isolates_configuration_and_never_inherits_authentication() {
        let parent = private_temp();
        let binary = script(parent.path(), "env");
        let runner =
            BoundedRunner::new(&binary, "unix:///var/run/docker.sock", parent.path()).unwrap();
        let output = runner.run(&[], Duration::from_secs(2), 8192).unwrap();
        for line in output.lines() {
            let key = line.split('=').next().unwrap();
            assert!(
                [
                    "PATH",
                    "HOME",
                    "DOCKER_CONFIG",
                    "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME",
                    "DOCKER_HOST",
                    "LANG",
                    "LC_ALL",
                    "PWD"
                ]
                .contains(&key),
                "unexpected inherited key"
            );
        }
        assert!(output.contains(&format!("HOME={}", runner.staging.path().display())));
        assert!(output.contains("DOCKER_HOST=unix:///var/run/docker.sock"));
    }
    #[test]
    fn stage_timeouts_are_bounded_and_keep_endpoint_checks() {
        let parent = private_temp();
        let binary = script(parent.path(), "exit 19");
        let docker = DockerRunner::new(
            &binary,
            "unix:///var/run/docker.sock",
            "test-engine",
            parent.path(),
        )
        .unwrap();
        for timeout in [Duration::ZERO, Duration::from_secs(901)] {
            assert_eq!(
                docker
                    .run_checked_with_timeout(&["pull", "image"], timeout)
                    .unwrap_err(),
                "invalid Docker operation timeout"
            );
        }
        assert!(docker
            .run_checked_with_timeout(
                &["pull", "-Htcp://remote", "image"],
                Duration::from_secs(600)
            )
            .unwrap_err()
            .contains("override"));
        // Even a long pull budget must inspect the expected engine first.
        assert!(docker
            .run_checked_with_timeout(&["pull", "image"], Duration::from_secs(600))
            .is_err());
    }
    #[test]
    fn bounds_real_process_output_timeout_and_redacts_failure() {
        let parent = private_temp();
        let binary = script(parent.path(), "while :; do printf 'secret'; done");
        let runner =
            BoundedRunner::new(&binary, "unix:///var/run/docker.sock", parent.path()).unwrap();
        assert!(runner
            .run(&[], Duration::from_secs(2), 64)
            .unwrap_err()
            .contains("exceeds"));
        script(parent.path(), "while :; do printf 'secret' >&2; done");
        assert!(runner
            .run(&[], Duration::from_secs(2), 64)
            .unwrap_err()
            .contains("exceeds"));
        script(parent.path(), "sleep 60 & wait");
        let started = Instant::now();
        assert!(runner
            .run(&[], Duration::from_millis(100), 64)
            .unwrap_err()
            .contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
        script(parent.path(), "printf 'credential-secret' >&2; exit 7");
        let error = runner.run(&[], Duration::from_secs(2), 1024).unwrap_err();
        assert!(!error.contains("credential-secret"));
    }
    #[test]
    fn successful_leader_does_not_leave_pipe_holding_child_running() {
        let parent = private_temp();
        // The sleeping child inherits both pipes after its parent exits. A
        // reader that waits for EOF without cancelling the owned group hangs.
        let binary = script(parent.path(), "sleep 60 & printf 'done'; exit 0");
        let runner =
            BoundedRunner::new(&binary, "unix:///var/run/docker.sock", parent.path()).unwrap();
        let started = Instant::now();
        assert_eq!(
            runner.run(&[], Duration::from_secs(2), 1024).unwrap(),
            "done"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn checks_real_stub_info_compose_and_identity_before_commands() {
        let parent = private_temp();
        let body = format!("case \"$1\" in info) printf '%s\\n' '{}' ;; compose) printf '2.39.0\\n' ;; *) exit 9 ;; esac", info());
        let binary = script(parent.path(), &body);
        let docker = DockerRunner::new(
            &binary,
            "unix:///var/run/docker.sock",
            "test-engine",
            parent.path(),
        )
        .unwrap();
        assert_eq!(docker.preflight().unwrap().compose_version, "2.39.0");
        assert!(docker.run_checked(&["--host=tcp://remote", "ps"]).is_err());
        assert!(docker.run_checked(&["ps", "-c", "unrelated"]).is_err());
        assert!(docker.run_checked(&["ps", "-cunrelated"]).is_err());
        script(parent.path(), &body.replace("test-engine", "replacement"));
        let refusal = docker.run_checked(&["compose", "version"]).unwrap_err();
        assert!(
            refusal.contains("identity"),
            "unexpected refusal: {refusal}"
        );
    }
    #[test]
    fn refuses_remote_endpoint_rootless_wrong_platform_and_unknown_fields() {
        let parent = private_temp();
        let binary = script(parent.path(), "exit 0");
        assert!(
            DockerRunner::new(&binary, "tcp://remote:2375", "test-engine", parent.path()).is_err()
        );
        for invalid in [
            info().replace("x86_64", "aarch64"),
            info().replace("linux", "windows"),
            info().replace("name=seccomp,profile=builtin", "name=rootless"),
            info().replace("name=seccomp,profile=builtin", "name=userns"),
            info().replace("name=seccomp,profile=builtin", "name=userns,remapped=true"),
            info().replace("test-engine", "other"),
            info().replacen('{', "{\"surprise\":true,", 1),
        ] {
            assert!(validate_info(&invalid, "test-engine").is_err());
        }
    }
}
