// Exercise the recorder's signal ownership with a live libtest and a child
// that ignores the first TERM. No database, Docker or product binary needed.
#[test]
fn holding() {
    let directory = std::env::var("MARTY_SIGNAL_PID_DIR").unwrap();
    std::fs::write(format!("{directory}/harness.pid"), std::process::id().to_string()).unwrap();
    let python = std::env::var("MARTY_SIGNAL_PYTHON").unwrap();
    let child = std::process::Command::new(python)
        .arg("-c")
        .arg(concat!(
            "import os,signal,time,pathlib\n",
            "def seen(signum, _frame):\n",
            " pathlib.Path(os.environ['MARTY_SIGNAL_PID_DIR'], 'received-signal').write_text(str(signum))\n",
            "signal.signal(signal.SIGTERM, seen)\n",
            "signal.signal(signal.SIGINT, seen)\n",
            "pathlib.Path(os.environ['MARTY_SIGNAL_PID_DIR'], 'descendant.pid').write_text(str(os.getpid()))\n",
            "time.sleep(120)\n",
        ))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(child.id() > 0);
    std::thread::sleep(std::time::Duration::from_secs(120));
}
