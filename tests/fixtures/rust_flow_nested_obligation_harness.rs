// A parent Flow-style libtest case captures a nested invocation's own
// summary. The outer evidence collector must see only its selected case.
#[test]
fn nested_parent() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "nested_child", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok."));
    println!("captured nested libtest child");
}

#[test]
fn nested_child() {
    println!("owned child diagnostic");
}
