//! Bounded read-only Compose renderer; no daemon commands or operator environment.
use crate::Result;
use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn compose(directory: &Path, args: &[String], executable: Option<&OsString>) -> Result<String> {
    let mut command =
        Command::new(executable.map_or_else(|| OsString::from("docker"), Clone::clone));
    if executable.is_none() {
        command.arg("compose");
    }
    command
        .args(args)
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::null());
    // Only executable/OS discovery, never application settings, proxy URLs or secrets.
    for key in [
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    capture_command(command, directory, Duration::from_secs(60), 8 * 1024 * 1024)
}

fn capture_command(
    mut command: Command,
    directory: &Path,
    deadline: Duration,
    limit: u64,
) -> Result<String> {
    let mut stdout = tempfile::tempfile().map_err(|_| "Cannot create renderer output")?;
    let stderr = tempfile::tempfile().map_err(|_| "Cannot create renderer diagnostic output")?;
    command
        .stdout(
            stdout
                .try_clone()
                .map_err(|_| "Cannot capture renderer output")?,
        )
        .stderr(
            stderr
                .try_clone()
                .map_err(|_| "Cannot capture renderer diagnostics")?,
        );
    let mut child = command.spawn().map_err(|_| {
        "docker compose is required to render the final self-host bundle compose file"
    })?;
    let start = Instant::now();
    let status = loop {
        // Polling is not a filesystem quota: kill/reap on the first observation
        // of excess output, and recheck after exit for a short-lived producer.
        let oversized = [&stdout, &stderr].iter().any(|file| {
            file.metadata()
                .map_or(true, |metadata| metadata.len() > limit)
        });
        if oversized {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Compose renderer output exceeds the package limit".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Compose renderer failed or exceeded its deadline".into());
            }
        }
    };
    if !status.success() {
        return Err("docker compose config failed; renderer diagnostics withheld to avoid disclosing configuration".into());
    }
    if [&stdout, &stderr].iter().any(|file| {
        file.metadata()
            .map_or(true, |metadata| metadata.len() > limit)
    }) {
        return Err("Compose renderer output exceeds the package limit".into());
    }
    use std::io::{Seek, SeekFrom};
    stdout
        .seek(SeekFrom::Start(0))
        .map_err(|_| "Cannot read renderer output")?;
    let mut text = String::new();
    stdout
        .read_to_string(&mut text)
        .map_err(|_| "Renderer output is not UTF-8")?;
    // Retain descriptor-provided paths; only the exact staged files are visible.
    if !fs::metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        return Err("Staging directory disappeared".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shell(windows: &str, unix: &str) -> Command {
        #[cfg(windows)]
        {
            let _ = unix;
            let mut command = Command::new("cmd.exe");
            command.args(["/D", "/C", windows]);
            command
        }
        #[cfg(not(windows))]
        {
            let _ = windows;
            let mut command = Command::new("sh");
            command.args(["-c", unix]);
            command
        }
    }
    #[test]
    fn stdout_and_stderr_limits_reap_controlled_producers_without_exposing_content() {
        for stderr in [false, true] {
            let owned = tempfile::tempdir().unwrap();
            let redirection = if stderr { " 1>&2" } else { "" };
            let command = shell(
                &format!("for /l %n in (1,1,10000) do @echo synthetic-sensitive-renderer-value{redirection}"),
                &format!("i=0; while [ $i -lt 10000 ]; do printf '%s\\n' synthetic-sensitive-renderer-value{redirection}; i=$((i+1)); done"),
            );
            let error =
                capture_command(command, owned.path(), Duration::from_secs(5), 128).unwrap_err();
            assert_eq!(error, "Compose renderer output exceeds the package limit");
            assert!(!error.contains("synthetic-sensitive"));
        }
    }
    #[test]
    fn failed_renderer_diagnostics_and_deadlines_are_closed() {
        let owned = tempfile::tempdir().unwrap();
        let command = shell(
            "echo synthetic-sensitive-renderer-value 1>&2 & exit /b 7",
            "printf '%s' synthetic-sensitive-renderer-value >&2; exit 7",
        );
        let error =
            capture_command(command, owned.path(), Duration::from_secs(5), 1024).unwrap_err();
        assert!(error.contains("diagnostics withheld"));
        assert!(!error.contains("synthetic-sensitive"));
        // Zero deadline forces the ownership branch immediately; no external waits or descendants.
        let command = shell(
            "for /l %n in (1,1,1000000) do @rem bounded synthetic loop",
            "while :; do :; done",
        );
        let error = capture_command(command, owned.path(), Duration::ZERO, 1024).unwrap_err();
        assert!(error.contains("deadline"));
    }
}
