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
