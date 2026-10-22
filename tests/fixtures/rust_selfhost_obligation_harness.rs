// Synthetic libtest protocol only: these names are deliberately not the
// product's 17-name roster, which remains owned by the shell runner.
#[test]
fn case01() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "case02", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok."));
    println!("nested child summary captured, not an outer result");
}
#[test]
fn case02() {}
#[test]
fn case03() {}
#[test]
fn case04() {}
#[test]
fn case05() {}
#[test]
fn case06() {}
#[test]
fn case07() {}
#[test]
fn case08() {}
#[test]
fn case09() {}
#[test]
fn case10() {}
#[test]
fn case11() {}
#[test]
fn case12() {
    assert!(std::env::var_os("MARTY_SELFHOST_SYNTHETIC_FAIL").is_none());
}
#[test]
fn case13() {}
#[test]
fn case14() {}
#[test]
fn case15() {}
#[test]
fn case16() {}
#[test]
fn case17() {}
