//! Bounded Linux subprocess execution and read-only Docker preflight.
//! No Docker resource is created by preflight. The caller owns all mutation
//! arguments and must persist resource ownership before using run_checked.
#![cfg(target_os = "linux")]

use crate::installer_state::{RuntimeBinding, RuntimeProfile};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{ErrorKind, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
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
struct HeldRootlessSocket(File);

fn endpoint_for_profile(host: &str, profile: RuntimeProfile) -> Result<Option<HeldRootlessSocket>> {
    endpoint(host)?;
    if profile == RuntimeProfile::Rootful {
        return Ok(None);
    }
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || host != format!("unix:///run/user/{uid}/docker.sock") {
        return Err("rootless Docker socket must belong to the installer user".into());
    }
    let path = Path::new(
        host.strip_prefix("unix://")
            .ok_or("invalid local Docker endpoint")?,
    );
    hold_rootless_socket(path, uid).map(Some)
}
fn checked_rootless_socket(path: &Path, uid: u32) -> Result<(u64, u64)> {
    trusted_ancestors(path)?;
    let parent = fs::symlink_metadata(path.parent().ok_or("rootless runtime unavailable")?)
        .map_err(|_| "rootless runtime unavailable")?;
    let socket = fs::symlink_metadata(path).map_err(|_| "rootless socket unavailable")?;
    if !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.uid() != uid
        || parent.mode() & 0o7777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != uid
    {
        return Err("rootless Docker socket custody differs".into());
    }
    Ok((socket.dev(), socket.ino()))
}
fn hold_rootless_socket(path: &Path, uid: u32) -> Result<HeldRootlessSocket> {
    let named = checked_rootless_socket(path, uid)?;
    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid rootless socket")?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("rootless socket unavailable".into());
    }
    let held = HeldRootlessSocket(unsafe { File::from_raw_fd(fd) });
    let metadata = held
        .0
        .metadata()
        .map_err(|_| "rootless socket unavailable")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || (metadata.dev(), metadata.ino()) != named
        || checked_rootless_socket(path, uid)? != named
    {
        return Err("rootless Docker socket custody differs".into());
    }
    Ok(held)
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
        let (output, _) = self.capture(args, timeout, limit)?;
        String::from_utf8(output).map_err(|_| "Docker command returned non-UTF8 output".into())
    }
    fn capture(
        &self,
        args: &[&str],
        timeout: Duration,
        limit: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
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
        let child = command.spawn().map_err(|error| {
            // Only OS classification is safe: never include executable paths,
            // arguments or inherited diagnostic contents in installer errors.
            format!(
                "cannot start Docker command (kind={:?}, errno={:?})",
                error.kind(),
                error.raw_os_error()
            )
        })?;
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
        Ok((output, diagnostic))
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
    // Older rootful journals and test fixtures do not require these fields.
    // Rootless memory admission below requires all three positive values.
    #[serde(default)]
    cgroup_version: Option<String>,
    #[serde(default)]
    cgroup_driver: Option<String>,
    #[serde(default)]
    memory_limit: Option<bool>,
}
#[derive(Debug, Serialize)]
pub struct DockerObservation {
    pub engine_id: String,
    pub os: String,
    pub architecture: String,
    pub server_version: String,
    pub compose_version: String,
}
fn compose_version_valid(version: &str) -> bool {
    // Distribution builds include suffixes such as +ds1-0ubuntu1~24.04.1.
    version.len() <= 128
        && regex::Regex::new(r"\Av?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.~-]+)?\z")
            .unwrap()
            .is_match(version)
}
fn validate_info_for_profile(
    output: &str,
    expected: &str,
    profile: RuntimeProfile,
) -> Result<DockerInfo> {
    let info: DockerInfo =
        serde_json::from_str(output).map_err(|_| "Docker info response is invalid")?;
    let mode = |name: &str| {
        info.security_options
            .iter()
            .any(|value| value == name || value.starts_with(&format!("{name},")))
    };
    let rootless = mode("name=rootless");
    let userns = mode("name=userns");
    let exact_rootless_count = info
        .security_options
        .iter()
        .filter(|option| option.as_str() == "name=rootless")
        .count();
    let rootless_marker_count = info
        .security_options
        .iter()
        .filter(|option| option.as_str() == "name=rootless" || option.starts_with("name=rootless,"))
        .count();
    if info.id != expected
        || !engine_id(&info.id)
        || info.os != "linux"
        || !matches!(info.architecture.as_str(), "amd64" | "x86_64")
        || match profile {
            RuntimeProfile::Rootful => rootless || userns,
            RuntimeProfile::Rootless => {
                !rootless || exact_rootless_count != 1 || rootless_marker_count != 1 || userns
            }
        }
        || info.server_version.is_empty()
        || info.server_version.len() > 128
    {
        return Err(match profile {
            RuntimeProfile::Rootful => {
                "Docker Engine identity, platform, or rootful policy differs"
            }
            RuntimeProfile::Rootless => {
                "Docker Engine identity, platform, or rootless policy differs"
            }
        }
        .into());
    }
    if profile == RuntimeProfile::Rootless
        && (info.cgroup_version.as_deref() != Some("2")
            || info.cgroup_driver.as_deref() != Some("systemd")
            || info.memory_limit != Some(true))
    {
        // Docker documents that rootless cgroup resource flags can be ignored
        // without cgroup v2 and systemd. This is a daemon prerequisite check,
        // not proof of a particular container's eventual kernel cgroup value.
        return Err(
            "rootless Docker memory limits require cgroup v2, systemd and memory-limit support"
                .into(),
        );
    }
    Ok(info)
}
#[cfg(test)]
fn validate_info(output: &str, expected: &str) -> Result<DockerInfo> {
    validate_info_for_profile(output, expected, RuntimeProfile::Rootful)
}

pub struct DockerRunner {
    runner: BoundedRunner,
    expected_engine_id: String,
    profile: RuntimeProfile,
    socket_identity: Option<HeldRootlessSocket>,
    deadline: Option<Instant>,
}
impl DockerRunner {
    /// Select the exact profile persisted with this installation. In particular,
    /// a rootless journal must never be reopened through the rootful constructor.
    pub fn from_binding(
        docker_executable: &Path,
        binding: &RuntimeBinding,
        private_parent: &Path,
    ) -> Result<Self> {
        binding.validate()?;
        Self::new_for_profile(
            docker_executable,
            &binding.docker_host,
            &binding.engine_id,
            private_parent,
            binding.profile,
        )
    }
    fn recheck_endpoint(&self) -> Result<()> {
        let host = self
            .runner
            .docker_host
            .as_deref()
            .ok_or("Docker endpoint unavailable")?;
        match self.profile {
            RuntimeProfile::Rootful => {
                endpoint(host)?;
                if self.socket_identity.is_some() {
                    return Err("rootless Docker socket changed".into());
                }
            }
            RuntimeProfile::Rootless => {
                let uid = unsafe { libc::geteuid() };
                if uid == 0 {
                    return Err("rootless Docker socket must belong to the installer user".into());
                }
                let path = Path::new(
                    host.strip_prefix("unix://")
                        .ok_or("invalid local Docker endpoint")?,
                );
                let held = self
                    .socket_identity
                    .as_ref()
                    .ok_or("rootless socket unavailable")?;
                let metadata = held
                    .0
                    .metadata()
                    .map_err(|_| "rootless socket unavailable")?;
                if !metadata.file_type().is_socket()
                    || metadata.uid() != uid
                    || checked_rootless_socket(path, uid)? != (metadata.dev(), metadata.ino())
                {
                    return Err("rootless Docker socket changed".into());
                }
            }
        }
        Ok(())
    }
    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
    fn budget(&self, limit: Duration) -> Result<Duration> {
        match self.deadline {
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .map(|remaining| remaining.min(limit))
                .ok_or_else(|| "Docker inspection deadline exceeded".into()),
            None => Ok(limit),
        }
    }
    /// Bounded application diagnostics for an already validated exact container.
    /// Callers must scrub both streams and re-observe ownership before output.
    pub(crate) fn capture_logs(&self, container: &str, tail: u16) -> Result<(String, String)> {
        if container.len() != 64
            || !container
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=1000).contains(&tail)
        {
            return Err("invalid bounded log request".into());
        }
        self.info()?;
        let (stdout, stderr) = self.runner.capture(
            &["logs", "--tail", &tail.to_string(), container],
            Duration::from_secs(30),
            MAX_OUTPUT,
        )?;
        let stdout = String::from_utf8(stdout).map_err(|_| "non-UTF8 application logs refused")?;
        let stderr = String::from_utf8(stderr).map_err(|_| "non-UTF8 application logs refused")?;
        self.info()?;
        Ok((stdout, stderr))
    }
    pub fn new(
        docker_executable: &Path,
        docker_host: &str,
        expected_engine_id: &str,
        private_parent: &Path,
    ) -> Result<Self> {
        Self::new_for_profile(
            docker_executable,
            docker_host,
            expected_engine_id,
            private_parent,
            RuntimeProfile::Rootful,
        )
    }
    /// Dormant rootless preflight primitive. A future reviewed installer path
    /// must persist the selected profile before using it for resource changes.
    pub(crate) fn new_for_profile(
        docker_executable: &Path,
        docker_host: &str,
        expected_engine_id: &str,
        private_parent: &Path,
        profile: RuntimeProfile,
    ) -> Result<Self> {
        if !engine_id(expected_engine_id) {
            return Err("invalid expected Docker Engine identity".into());
        }
        let socket_identity = endpoint_for_profile(docker_host, profile)?;
        let runner = BoundedRunner::new(docker_executable, docker_host, private_parent)?;
        if profile == RuntimeProfile::Rootless {
            crate::installer_compose_plugin::admit_current_user_compose(runner.staging.path())?;
        }
        Ok(Self {
            runner,
            expected_engine_id: expected_engine_id.into(),
            profile,
            socket_identity,
            deadline: None,
        })
    }
    fn info(&self) -> Result<DockerInfo> {
        self.recheck_endpoint()?;
        let output = self.runner.run(&["info", "--format", "{\"id\":{{json .ID}},\"os\":{{json .OSType}},\"architecture\":{{json .Architecture}},\"server_version\":{{json .ServerVersion}},\"security_options\":{{json .SecurityOptions}},\"cgroup_version\":{{json .CgroupVersion}},\"cgroup_driver\":{{json .CgroupDriver}},\"memory_limit\":{{json .MemoryLimit}}}"], self.budget(Duration::from_secs(30))?, 65536)?;
        self.recheck_endpoint()?;
        validate_info_for_profile(&output, &self.expected_engine_id, self.profile)
    }
    /// Read-only Docker checks, using the isolated configuration and fixed socket.
    pub fn preflight(&self) -> Result<DockerObservation> {
        let info = self.info()?;
        let compose_version = self
            .runner
            .run(
                &["compose", "version", "--short"],
                self.budget(Duration::from_secs(30))?,
                1024,
            )?
            .trim()
            .to_owned();
        if !compose_version_valid(&compose_version) {
            return Err("Docker Compose plugin version unavailable".into());
        }
        self.recheck_endpoint()?;
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
                    | &"stop"
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
        self.recheck_endpoint()?;
        let output = self.runner.run(args, self.budget(timeout)?, MAX_OUTPUT)?;
        self.recheck_endpoint()?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    #[test]
    fn distribution_compose_versions_remain_bounded_metadata() {
        assert!(super::compose_version_valid("2.40.3+ds1-0ubuntu1~24.04.1"));
        for invalid in [
            "2.40.3~ubuntu",
            "2.40.3+bad suffix",
            "2.40.3+bad\n",
            "2.40.3+bad/path",
            "2.40.3+$(id)",
        ] {
            assert!(!super::compose_version_valid(invalid));
        }
        assert!(!super::compose_version_valid(&format!(
            "2.40.3+{}",
            "a".repeat(122)
        )));
    }
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
    fn rootless_info() -> String {
        r#"{"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=rootless"],"cgroup_version":"2","cgroup_driver":"systemd","memory_limit":true}"#.into()
    }
    #[test]
    fn selected_profile_requires_positive_daemon_mode_and_exact_engine() {
        let rootless = rootless_info();
        assert!(validate_info_for_profile(info(), "test-engine", RuntimeProfile::Rootful).is_ok());
        assert!(
            validate_info_for_profile(&rootless, "test-engine", RuntimeProfile::Rootless).is_ok()
        );
        assert!(
            validate_info_for_profile(info(), "test-engine", RuntimeProfile::Rootless).is_err()
        );
        assert!(
            validate_info_for_profile(&rootless, "test-engine", RuntimeProfile::Rootful).is_err()
        );
        assert!(
            validate_info_for_profile(&rootless, "changed-engine", RuntimeProfile::Rootless)
                .is_err()
        );
        assert!(validate_info_for_profile(
            &rootless.replace("name=rootless", "name=userns"),
            "test-engine",
            RuntimeProfile::Rootless
        )
        .is_err());
        for ambiguous in [
            rootless.replace("name=rootless", "name=rootless,disabled"),
            rootless.replace("name=rootless", "name=rootless\",\"name=rootless"),
            rootless.replace("name=rootless", "name=rootless\",\"name=rootless,disabled"),
        ] {
            assert!(
                validate_info_for_profile(&ambiguous, "test-engine", RuntimeProfile::Rootless)
                    .is_err()
            );
        }
        assert!(validate_info_for_profile(
            &rootless.replace("name=rootless", "name=rootless,enabled\",\"name=userns"),
            "test-engine",
            RuntimeProfile::Rootless
        )
        .is_err());
        for (field, wrong) in [
            ("cgroup_version", serde_json::json!("1")),
            ("cgroup_driver", serde_json::json!("none")),
            ("cgroup_driver", serde_json::json!("cgroupfs")),
            ("memory_limit", serde_json::json!(false)),
            ("memory_limit", serde_json::Value::Null),
        ] {
            let mut changed: serde_json::Value = serde_json::from_str(&rootless).unwrap();
            changed[field] = wrong;
            assert!(validate_info_for_profile(
                &changed.to_string(),
                "test-engine",
                RuntimeProfile::Rootless
            )
            .is_err());
        }
        for missing in ["cgroup_version", "cgroup_driver", "memory_limit"] {
            let mut changed: serde_json::Value = serde_json::from_str(&rootless).unwrap();
            changed.as_object_mut().unwrap().remove(missing);
            assert!(validate_info_for_profile(
                &changed.to_string(),
                "test-engine",
                RuntimeProfile::Rootless
            )
            .is_err());
        }
        let rootful_legacy: serde_json::Value = serde_json::from_str(info()).unwrap();
        assert!(rootful_legacy.get("cgroup_version").is_none());
        assert!(validate_info_for_profile(info(), "test-engine", RuntimeProfile::Rootful).is_ok());
        let rootful_cgroupfs = info().replacen(
            "\"security_options\":",
            "\"cgroup_version\":\"1\",\"cgroup_driver\":\"cgroupfs\",\"memory_limit\":false,\"security_options\":",
            1,
        );
        assert!(validate_info_for_profile(
            &rootful_cgroupfs,
            "test-engine",
            RuntimeProfile::Rootful
        )
        .is_ok());
    }
    #[test]
    fn rootless_socket_custody_requires_private_owned_parent_and_socket_inode() {
        let parent = private_temp();
        let socket = parent.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let uid = unsafe { libc::geteuid() };
        let first = checked_rootless_socket(&socket, uid).unwrap();
        assert_ne!(first.1, 0);
        let replacement = parent.path().join("replacement.sock");
        let other = UnixListener::bind(&replacement).unwrap();
        let second = checked_rootless_socket(&replacement, uid).unwrap();
        assert_ne!(second, first);
        fs::rename(&replacement, &socket).unwrap();
        assert_eq!(checked_rootless_socket(&socket, uid).unwrap(), second);
        let alias = parent.path().join("alias.sock");
        symlink(&socket, &alias).unwrap();
        assert!(checked_rootless_socket(&alias, uid).is_err());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(checked_rootless_socket(&socket, uid).is_err());
        drop(listener);
        drop(other);
    }
    #[test]
    fn rootless_runner_refuses_mode_engine_and_socket_drift_before_next_command() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let parent = private_temp();
        let socket = parent.path().join("docker.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let info_path = parent.path().join("engine-info.json");
        let rootless = rootless_info();
        fs::write(&info_path, &rootless).unwrap();
        let binary = script(
            parent.path(),
            r#"case "$1" in
info) cat "${0%/*}/engine-info.json" ;;
compose) printf c >> "${0%/*}/compose-calls"; printf '2.40.3\n' ;;
ps) printf x >> "${0%/*}/resource-calls"; printf 'owned' ;;
*) exit 9 ;;
esac"#,
        );
        // The production constructor admits only /run/user/<uid>/docker.sock.
        // Construct the same runner state with a private test socket to prove
        // the per-command guard without touching any host Docker endpoint.
        assert!(DockerRunner::new_for_profile(
            &binary,
            &format!("unix://{}", socket.display()),
            "test-engine",
            parent.path(),
            RuntimeProfile::Rootless,
        )
        .is_err());
        let docker = DockerRunner {
            runner: BoundedRunner::new(
                &binary,
                &format!("unix://{}", socket.display()),
                parent.path(),
            )
            .unwrap(),
            expected_engine_id: "test-engine".into(),
            profile: RuntimeProfile::Rootless,
            socket_identity: Some(
                hold_rootless_socket(&socket, unsafe { libc::geteuid() }).unwrap(),
            ),
            deadline: None,
        };
        assert!(docker.preflight().is_ok());
        let compose_calls = fs::read(parent.path().join("compose-calls")).unwrap();
        assert_eq!(docker.run_checked(&["ps"]).unwrap(), "owned");
        let calls = fs::read(parent.path().join("resource-calls")).unwrap();
        for changed in [
            info().to_owned(),
            rootless.replace("test-engine", "other-engine"),
            rootless.replace("\"cgroup_version\":\"2\"", "\"cgroup_version\":\"1\""),
            rootless.replace(
                "\"cgroup_driver\":\"systemd\"",
                "\"cgroup_driver\":\"none\"",
            ),
            rootless.replace("\"memory_limit\":true", "\"memory_limit\":false"),
        ] {
            fs::write(&info_path, changed).unwrap();
            assert!(docker.preflight().is_err());
            assert_eq!(
                fs::read(parent.path().join("compose-calls")).unwrap(),
                compose_calls
            );
            assert!(docker.run_checked(&["ps"]).is_err());
            assert_eq!(
                fs::read(parent.path().join("resource-calls")).unwrap(),
                calls
            );
        }
        fs::write(&info_path, rootless).unwrap();
        let other_path = parent.path().join("other.sock");
        let _other = UnixListener::bind(&other_path).unwrap();
        fs::rename(&other_path, &socket).unwrap();
        assert!(docker.run_checked(&["ps"]).is_err());
        assert_eq!(
            fs::read(parent.path().join("resource-calls")).unwrap(),
            calls
        );
        let held_fd = docker.socket_identity.as_ref().unwrap().0.as_raw_fd();
        assert_ne!(
            unsafe { libc::fcntl(held_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(docker);
        assert_eq!(unsafe { libc::fcntl(held_fd, libc::F_GETFD) }, -1);
    }
    #[test]
    fn diagnostic_capture_bounds_arguments_and_keeps_both_streams_private() {
        let parent = private_temp();
        let binary = script(parent.path(), &format!(
            "if [ \"$1\" = info ]; then printf '%s' '{}'; else printf 'stdout-secret'; printf 'stderr-secret' >&2; fi", info()));
        let docker = DockerRunner::new(
            &binary,
            "unix:///var/run/docker.sock",
            "test-engine",
            parent.path(),
        )
        .unwrap();
        let id = "a".repeat(64);
        assert_eq!(
            docker.capture_logs(&id, 10).unwrap(),
            ("stdout-secret".into(), "stderr-secret".into())
        );
        for tail in [0, 1001] {
            assert!(docker.capture_logs(&id, tail).is_err());
        }
        for bad in ["--follow", "name", "../../foreign"] {
            assert!(docker.capture_logs(bad, 10).is_err());
        }
        script(parent.path(), &format!(
            "if [ \"$1\" = info ]; then printf '%s' '{}'; else printf 'stdout-secret'; printf 'stderr-secret' >&2; exit 9; fi", info()));
        let error = docker.capture_logs(&id, 10).unwrap_err();
        assert!(!error.contains("secret"));
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
    fn shared_validation_deadline_bounds_engine_checks_before_launch() {
        let parent = private_temp();
        let binary = script(parent.path(), "sleep 10");
        let docker = DockerRunner::new(
            &binary,
            "unix:///var/run/docker.sock",
            "test-engine",
            parent.path(),
        )
        .unwrap()
        .with_deadline(Instant::now() + Duration::from_millis(100));
        let started = Instant::now();
        assert!(docker.preflight().is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(docker.run_checked(&["inspect", "container"]).is_err());
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
        // Model a daemon identity change without rewriting the Docker client.
        // Replacing executable text is unrelated to the identity policy and can
        // encounter Linux ETXTBSY when another process retains a writer fd.
        let info_path = parent.path().join("engine-info.json");
        fs::write(&info_path, info()).unwrap();
        let binary = script(
            parent.path(),
            r#"case "$1" in
info) cat "${0%/*}/engine-info.json" ;;
compose) printf x >> "${0%/*}/compose-calls"; printf '2.39.0\n' ;;
*) exit 9 ;;
esac"#,
        );
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
        let calls = fs::read(parent.path().join("compose-calls")).unwrap();
        fs::write(&info_path, info().replace("test-engine", "replacement")).unwrap();
        let refusal = docker.run_checked(&["compose", "version"]).unwrap_err();
        assert!(
            refusal.contains("identity"),
            "unexpected refusal: {refusal}"
        );
        assert_eq!(
            fs::read(parent.path().join("compose-calls")).unwrap(),
            calls,
            "identity mismatch must refuse before executing the requested command"
        );
    }
    #[test]
    fn preflight_refuses_when_isolated_cli_has_no_compose_plugin() {
        let parent = private_temp();
        fs::write(parent.path().join("engine-info.json"), info()).unwrap();
        let binary = script(
            parent.path(),
            "case \"$1\" in info) cat \"${0%/*}/engine-info.json\" ;; compose) exit 42 ;; *) exit 9 ;; esac",
        );
        let docker = DockerRunner::new(
            &binary,
            "unix:///var/run/docker.sock",
            "test-engine",
            parent.path(),
        )
        .unwrap();
        assert!(docker.preflight().is_err());
        assert!(!parent.path().join("cli-plugins").exists());
    }
    #[test]
    fn persisted_binding_selects_profile_without_rootful_fallback() {
        let parent = private_temp();
        let info_path = parent.path().join("engine-info.json");
        fs::write(&info_path, info()).unwrap();
        let binary = script(
            parent.path(),
            "case \"$1\" in info) cat \"${0%/*}/engine-info.json\" ;; compose) printf '2.39.0\\n' ;; *) exit 9 ;; esac",
        );
        // Historical journals omit profile and remain explicitly Rootful.
        let binding: RuntimeBinding = serde_json::from_value(serde_json::json!({
            "docker_host": "unix:///var/run/docker.sock",
            "engine_id": "test-engine",
            "openbao_port": 18200
        }))
        .unwrap();
        assert_eq!(binding.profile, RuntimeProfile::Rootful);
        let docker = DockerRunner::from_binding(&binary, &binding, parent.path()).unwrap();
        assert_eq!(docker.profile, RuntimeProfile::Rootful);
        assert!(docker.preflight().is_ok());
        fs::write(
            &info_path,
            info().replace("name=seccomp,profile=builtin", "name=rootless"),
        )
        .unwrap();
        assert!(docker.preflight().is_err());
        let rootless = RuntimeBinding {
            profile: RuntimeProfile::Rootless,
            ..binding
        };
        // A rootless journal cannot be reopened through the rootful socket.
        assert!(DockerRunner::from_binding(&binary, &rootless, parent.path()).is_err());
    }
    #[test]
    fn executable_writer_failure_reports_only_os_classification() {
        let parent = private_temp();
        let binary = script(parent.path(), "printf 'credential-secret' >&2; exit 0");
        let runner =
            BoundedRunner::new(&binary, "unix:///var/run/docker.sock", parent.path()).unwrap();
        // Linux deterministically refuses exec while this inode has a writer.
        // This characterizes ETXTBSY; it does not establish the errno of a past
        // intermittent failure whose original OS classification was unavailable.
        let writer = fs::OpenOptions::new().write(true).open(&binary).unwrap();
        let error = runner
            .run(&["credential-secret"], Duration::from_secs(2), 1024)
            .unwrap_err();
        drop(writer);
        assert!(error.contains("kind=ExecutableFileBusy"), "{error}");
        assert!(
            error.contains(&format!("errno=Some({})", libc::ETXTBSY)),
            "{error}"
        );
        assert!(!error.contains(binary.to_str().unwrap()));
        assert!(!error.contains("credential-secret"));
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
