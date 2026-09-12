//! Shared owned-process capture for synthetic renderers and Docker fixture CLI.
//! Regular files avoid pipe/reader-thread hangs; no process groups are targeted.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(super) enum CommandFailure {
    Io(std::io::Error),
    TimedOut,
    OutputTooLarge,
    TerminationFailed,
}

impl From<std::io::Error> for CommandFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct CaptureFiles(PathBuf);

impl CaptureFiles {
    fn new() -> std::io::Result<Self> {
        let parent = std::env::temp_dir().canonicalize()?;
        let path = parent.join(format!("marty-fixture-command-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn create(&self, name: &str) -> std::io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.0.join(name))
    }

    fn read(&self, name: &str, limit: u64) -> Result<Vec<u8>, CommandFailure> {
        let mut bytes = Vec::new();
        File::open(self.0.join(name))?
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            Err(CommandFailure::OutputTooLarge)
        } else {
            Ok(bytes)
        }
    }
}

impl Drop for CaptureFiles {
    fn drop(&mut self) {
        // Exact newly created files only, with no recursive deletion/link walk.
        for name in ["input.bin", "output.bin", "error.bin"] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

struct OwnedChild(Child, bool);

pub(super) fn stop_owned_child(child: &mut Child) -> Result<(), CommandFailure> {
    let reaped = |child: &mut Child| {
        child
            .try_wait()
            .map_err(|_| CommandFailure::TerminationFailed)
    };
    if reaped(child)?.is_some() {
        return Ok(());
    }
    // The child may finish between try_wait and kill, on either platform.
    if child.kill().is_err() && reaped(child)?.is_none() {
        return Err(CommandFailure::TerminationFailed);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if reaped(child)?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(CommandFailure::TerminationFailed)
}

impl OwnedChild {
    fn stop(&mut self) -> Result<(), CommandFailure> {
        self.1 = true;
        stop_owned_child(&mut self.0)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.1 && self.stop().is_err() {
            eprintln!("Owned fixture command cleanup requires inspection");
        }
    }
}

fn capture(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
    limit: u64,
    files: &CaptureFiles,
) -> Result<Output, CommandFailure> {
    if timeout.is_zero() {
        return Err(CommandFailure::TimedOut);
    }
    if let Some(input) = input {
        files.create("input.bin")?.write_all(input)?;
        command.stdin(File::open(files.0.join("input.bin"))?);
    } else {
        command.stdin(Stdio::null());
    }
    let output = files.create("output.bin")?;
    let errors = files.create("error.bin")?;
    command
        .stdout(output.try_clone()?)
        .stderr(errors.try_clone()?);
    let mut child = OwnedChild(command.spawn()?, false);
    let deadline = Instant::now() + timeout;
    let result = (|| loop {
        if output.metadata()?.len() > limit || errors.metadata()?.len() > limit {
            return Err(CommandFailure::OutputTooLarge);
        }
        if let Some(status) = child.0.try_wait()? {
            return Ok(Output {
                status,
                stdout: files.read("output.bin", limit)?,
                stderr: files.read("error.bin", limit)?,
            });
        }
        if Instant::now() >= deadline {
            return Err(CommandFailure::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    })();
    child.stop()?;
    result
}

pub(super) fn run(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
    limit: u64,
) -> Result<Output, CommandFailure> {
    let files = CaptureFiles::new()?;
    let result = capture(command, input, timeout, limit, &files);
    // Release Command-owned file handles before exact file cleanup on Windows.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_child() {
        let Ok(mode) = std::env::var("MARTY_BOUNDED_COMMAND_TEST_MODE") else {
            return;
        };
        match mode.as_str() {
            "hang" => std::thread::sleep(Duration::from_secs(30)),
            "oversize" => {
                std::io::stdout().write_all(&vec![b'x'; 262145]).unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "stderr-oversize" => {
                std::io::stderr().write_all(&vec![b'x'; 262145]).unwrap();
                std::io::stderr().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "spawn-marker" => {
                let marker = std::env::var_os("MARTY_BOUNDED_COMMAND_SPAWN_MARKER").unwrap();
                std::fs::write(marker, b"spawned").unwrap();
                std::process::exit(0);
            }
            "nonzero" => {
                eprintln!("synthetic-private-canary");
                std::process::exit(23);
            }
            "success" => {
                let mut input = String::new();
                std::io::stdin().read_to_string(&mut input).unwrap();
                println!("bounded-success:{input}");
                std::process::exit(0);
            }
            _ => std::process::exit(24),
        }
    }

    fn child(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "bounded_fixture_command::tests::command_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MARTY_BOUNDED_COMMAND_TEST_MODE", mode);
        command
    }

    #[test]
    fn actual_hung_oversize_nonzero_success_commands_have_bounded_owned_cleanup() {
        for (mode, expected) in [
            ("hang", "timeout"),
            ("oversize", "size"),
            ("stderr-oversize", "size"),
            ("nonzero", "exit"),
            ("success", "success"),
        ] {
            let files = CaptureFiles::new().unwrap();
            let directory = files.0.clone();
            let mut command = child(mode);
            let started = Instant::now();
            let result = capture(
                &mut command,
                Some(b"synthetic-input"),
                Duration::from_secs(2),
                262144,
                &files,
            );
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            match (expected, result) {
                ("timeout", Err(CommandFailure::TimedOut))
                | ("size", Err(CommandFailure::OutputTooLarge)) => {}
                ("exit", Ok(output)) => {
                    assert_eq!(output.status.code(), Some(23));
                    assert!(String::from_utf8(output.stderr)
                        .unwrap()
                        .contains("synthetic-private-canary"));
                }
                ("success", Ok(output)) => {
                    assert!(output.status.success());
                    assert!(String::from_utf8(output.stdout)
                        .unwrap()
                        .contains("bounded-success:synthetic-input"));
                }
                _ => panic!("controlled command did not reach expected bounded outcome"),
            }
            assert!(started.elapsed() < Duration::from_secs(10));
            drop(files);
            assert!(
                !directory.exists(),
                "owned capture directory must be removed"
            );
        }
    }

    #[test]
    fn zero_deadline_does_not_spawn_or_create_capture_files() {
        let files = CaptureFiles::new().unwrap();
        let directory = files.0.clone();
        let marker = directory.join("must-not-exist");
        let mut command = child("spawn-marker");
        command.env("MARTY_BOUNDED_COMMAND_SPAWN_MARKER", &marker);
        assert!(matches!(
            capture(&mut command, None, Duration::ZERO, 1024, &files),
            Err(CommandFailure::TimedOut)
        ));
        assert!(!marker.exists());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        // An invalid executable must also yield the deadline, not a spawn error.
        assert!(matches!(
            run(
                &mut Command::new(directory.join("no-executable")),
                None,
                Duration::ZERO,
                1024
            ),
            Err(CommandFailure::TimedOut)
        ));
        drop(files);
        assert!(!directory.exists());
    }
}
