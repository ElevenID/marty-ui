// A real stable libtest harness: discovery does not say which listed tests are
// ignored, while default, --ignored, --include-ignored and --exact differ.
#[test]
fn happy() {
    // Like the composite contract's timer, bypass libtest's diagnostic capture.
    use std::io::Write;
    std::io::stderr()
        .write_all(b"\nMARTY_CI_PHASE_V1 {\"phase\":\"contract_phase\"}\n")
        .unwrap();
    // Like the migration executable's tracing JSON, bypass capture and split
    // libtest's human-readable `test happy ... ok` record across several lines.
    std::io::stdout()
        .write_all(b"{\"diagnostic\":\"direct-stdout\"}\n")
        .unwrap();
    #[cfg(windows)]
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "echo child-inherited-stdout"])
        .status();
    #[cfg(not(windows))]
    let status = std::process::Command::new("sh")
        .args(["-c", "printf 'child-inherited-stdout\\n'"])
        .status();
    assert!(status.unwrap().success());
    println!("captured successful diagnostic");
}

#[test]
fn happy_extra() {}

#[test]
#[ignore = "owned disposable fixture"]
fn fixture_case() {}

#[test]
#[ignore]
fn fixture_case_extra() {
    assert!(std::env::var_os("MARTY_LIBTEST_FORCE_FAILURE").is_none());
}
