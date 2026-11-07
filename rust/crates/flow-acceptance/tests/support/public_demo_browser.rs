//! Bounded owned Node/Chromium worker; only public loopback URLs cross stdin.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdout, Command, Stdio},
};

pub struct BrowserWorker {
    child: Child,
    output: BufReader<ChildStdout>,
    pub origin: String,
}
impl Drop for BrowserWorker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // EOF lets the owned worker close Chromium/Vite before forcefully
            // terminating only that worker if graceful shutdown stalls.
            drop(self.child.stdin.take());
            for _ in 0..50 {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
impl BrowserWorker {
    pub fn start(gateway: &str) -> Self {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../ui/scripts/public-verification-browser.mjs")
            .canonicalize()
            .unwrap();
        let mut command = Command::new("node");
        command
            .current_dir(script.parent().unwrap())
            .arg(script.file_name().unwrap())
            .arg(gateway)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for name in [
            "PATH",
            "SystemRoot",
            "SYSTEMROOT",
            "USERPROFILE",
            "HOME",
            "LOCALAPPDATA",
            "APPDATA",
            "TEMP",
            "TMP",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().expect("owned browser worker");
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut worker = Self {
            child,
            output,
            origin: String::new(),
        };
        let ready = worker.read("MARTY_BROWSER_READY ");
        worker.origin = ready["origin"].as_str().unwrap().into();
        let url = reqwest::Url::parse(&worker.origin).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        worker
    }
    fn read(&mut self, prefix: &str) -> Value {
        for _ in 0..100 {
            let mut line = String::new();
            assert!(
                self.output.read_line(&mut line).unwrap() > 0,
                "browser worker exited before receipt"
            );
            if let Some(json) = line.trim().strip_prefix(prefix) {
                return serde_json::from_str(json).unwrap();
            }
        }
        panic!("browser receipt missing")
    }
    pub fn run(mut self) -> Value {
        let input = self.child.stdin.as_mut().unwrap();
        input.write_all(b"RUN\n").unwrap();
        input.flush().unwrap();
        let result = self.read("MARTY_BROWSER_RESULT ");
        assert!(
            self.child.wait().unwrap().success(),
            "browser worker failed"
        );
        for field in [
            "verified",
            "reloadDidNotRelaunch",
            "walletRequestCancelled",
            "customizedDenialVerified",
            "chromiumExited",
            "viteClosed",
            "productionBundle",
        ] {
            assert_eq!(result[field], true, "{field}");
        }
        println!(
            "PUBLIC_DEMO_BROWSER_QUALIFIED {}",
            serde_json::json!({
            "verified":result["verified"],"reloadDidNotRelaunch":result["reloadDidNotRelaunch"],
            "walletRequestCancelled":result["walletRequestCancelled"],"chromiumPid":result["chromiumPid"],
            "customizedDenialVerified":result["customizedDenialVerified"],
            "browserVersion":result["browserVersion"],
            "productionBundle":result["productionBundle"],
            "chromiumExited":result["chromiumExited"],"viteClosed":result["viteClosed"]})
        );
        result
    }
}
