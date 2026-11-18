use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use marty_release_evidence::deployment_bundle::FILENAMES;

fn execute(mode: &str, input: &Path, output: &Path, stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_beta-evidence-bundle"))
        .arg(mode)
        .arg(input)
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

#[test]
fn roundtrip_is_byte_exact_and_refuses_overwrites() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("証拠");
    fs::create_dir(&input).unwrap();
    let original = b"\xef\xbb\xbf{\"n\":184467440737095516160,\"n\":null}\r\n";
    for name in FILENAMES {
        fs::write(input.join(name), original).unwrap();
    }
    let transport = temp.path().join("transport.json");
    assert!(execute("pack", &input, &transport, None).status.success());
    let packed = fs::read(&transport).unwrap();
    assert!(!execute("pack", &input, &transport, None).status.success());
    assert_eq!(fs::read(&transport).unwrap(), packed);
    let output = temp.path().join("output");
    assert!(execute("unpack", &transport, &output, None)
        .status
        .success());
    for name in FILENAMES {
        assert_eq!(fs::read(input.join(name)).unwrap(), original);
        assert_eq!(fs::read(output.join(name)).unwrap(), original);
    }
    assert_eq!(fs::read_dir(&output).unwrap().count(), 3);
    assert!(!execute("unpack", &transport, &output, None)
        .status
        .success());
    let streamed = temp.path().join("streamed");
    assert!(execute("unpack", Path::new("-"), &streamed, Some(&packed))
        .status
        .success());
    for name in FILENAMES {
        assert_eq!(fs::read(streamed.join(name)).unwrap(), original);
    }
    let event = serde_json::to_vec(&serde_json::json!({
        "inputs": {"deployment_evidence": String::from_utf8(packed).unwrap()},
    }))
    .unwrap();
    let event_output = temp.path().join("event-output");
    let result = execute("unpack-event", Path::new("-"), &event_output, Some(&event));
    assert!(result.status.success());
    assert!(!String::from_utf8(result.stdout)
        .unwrap()
        .contains("payload"));
    for name in FILENAMES {
        assert_eq!(fs::read(event_output.join(name)).unwrap(), original);
    }
}

#[test]
fn invalid_evidence_never_creates_outputs_or_echoes_input() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    let rejected = execute(
        "unpack",
        Path::new("-"),
        &output,
        Some(b"private-value-not-json"),
    );
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!String::from_utf8(rejected.stderr)
        .unwrap()
        .contains("private-value"));
    assert!(!output.exists());
    assert!(!execute("pack", temp.path(), &output, None).status.success());
    assert!(!output.exists());
    fs::create_dir(temp.path().join(FILENAMES[0])).unwrap();
    assert!(!execute("pack", temp.path(), &output, None).status.success());
    assert!(!output.exists());
}
