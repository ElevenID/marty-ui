// A real stable libtest harness: discovery does not say which listed tests are
// ignored, while default, --ignored, --include-ignored and --exact differ.
#[test]
fn happy() {
    // Like the composite contract's timer, bypass libtest's diagnostic capture.
    use std::io::Write;
    std::io::stderr()
        .write_all(b"\nMARTY_CI_PHASE_V1 {\"phase\":\"contract_phase\"}\n")
        .unwrap();
    println!("captured successful diagnostic");
}

#[test]
fn happy_extra() {}

#[test]
#[ignore = "owned disposable fixture"]
fn fixture_case() {}

#[test]
#[ignore]
fn fixture_case_extra() {}
