//! Existing bounded native child ownership and known-session self-retirement.
//! Shared by installer and Kubernetes batches; neither can revoke orphan leaves.
#![cfg(target_os = "linux")]
use crate::operator_http;
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Orphan generation input refused";
const RECOVERY: &str = "Orphan generation incomplete; retain owned helper and surviving outputs; unknown orphan leaves may remain";
const EXECUTABLE: &str = "/usr/local/bin/marty-passport-tls-bootstrap";
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
struct OwnedChild {
    child: Child,
    reaped: bool,
}
impl OwnedChild {
    fn kill(&self) {
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
    }
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        require(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
        )?;
        Ok(unsafe { info.si_pid() } != 0)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill();
            let _ = self.child.wait();
        }
    }
}
pub(crate) fn run_child(
    executable: &Path,
    env: &BTreeMap<String, String>,
    cwd: &Path,
    timeout: Duration,
) -> Result<()> {
    require(timeout > Duration::ZERO && timeout <= Duration::from_secs(600))?;
    let child = Command::new(executable)
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| RECOVERY)?;
    let mut owned = OwnedChild {
        child,
        reaped: false,
    };
    let deadline = Instant::now() + timeout;
    while !owned.exited()? {
        if Instant::now() >= deadline {
            return Err(RECOVERY.into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Reserve leader PID until all same-group descendants are killed, even on success.
    owned.kill();
    let status = owned.child.wait().map_err(|_| RECOVERY)?;
    owned.reaped = true;
    if status.success() {
        Ok(())
    } else {
        Err(RECOVERY.into())
    }
}
pub(crate) fn workload_executable() -> Result<()> {
    let path = Path::new(EXECUTABLE);
    require(path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| REFUSED)?;
    let metadata = file.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && metadata.len() > 0
            && metadata.len() <= 512 * 1024 * 1024,
    )?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(unsafe { libc::fstatvfs(file.as_raw_fd(), info.as_mut_ptr()) } == 0)?;
    require(unsafe { info.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}
pub(crate) async fn retire(bao: &OpenBaoHttp, token: &str) -> Result<()> {
    operator_http::request(
        bao,
        Method::POST,
        "auth/token/revoke-self",
        Some(&json!({})),
        Some(token),
    )
    .await
    .map_err(|_| RECOVERY)?;
    let response = operator_http::builder(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(token),
    )
    .send()
    .await
    .map_err(|_| RECOVERY)?;
    require(response.status() == StatusCode::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn private() -> tempfile::TempDir {
        let result = tempfile::tempdir().unwrap();
        std::fs::set_permissions(result.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        result
    }
    fn script(root: &Path, body: &str) -> std::path::PathBuf {
        let path = root.join(format!("child-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn real_child_timeout_and_failure_are_redacted_and_success_cancels_descendants() {
        let temp = private();
        let env = BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]);
        let child = script(temp.path(), "printf secret >&2; sleep 30 & wait");
        let started = Instant::now();
        let error = run_child(&child, &env, temp.path(), Duration::from_millis(100)).unwrap_err();
        assert!(!error.contains("secret"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let child = script(temp.path(), "sleep 30 & echo $! > descendant; exit 0");
        run_child(&child, &env, temp.path(), Duration::from_secs(2)).unwrap();
        let pid = std::fs::read_to_string(temp.path().join("descendant")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()));
            if match &observed {
                Err(_) => true,
                Ok(stat) => stat.split_whitespace().nth(2) == Some("Z"),
            } {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned descendant survived cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
