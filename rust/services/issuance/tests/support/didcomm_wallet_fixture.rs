//! Exact-owned synthetic HTTPS wallet. No deployment endpoints or keys are accepted.
use std::{
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use serde_json::Value;

use super::issuance_process::ChildGuard;

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        // Canonicalize for ownership verification, not the subprocess argument:
        // Windows verbatim (\\?\) paths are rejected by Git's OpenSSL executable.
        let parent = std::env::temp_dir();
        assert!(parent.is_absolute(), "test temp root must be absolute");
        let resolved_parent = parent.canonicalize().expect("resolve test temp root");
        let path = parent.join(format!("marty-didcomm-wallet-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create exact-owned wallet directory");
        let owned = Self(path);
        assert_eq!(
            owned
                .0
                .canonicalize()
                .expect("resolve owned directory")
                .parent(),
            Some(resolved_parent.as_path()),
            "created wallet directory stays within the resolved test root"
        );
        owned
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        // Never follow a replacement link or recursively remove a caller's path.
        if let Ok(metadata) = std::fs::symlink_metadata(&self.0) {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}

pub(super) struct WalletFixture {
    // Drop the child before its certificate directory, including during unwinding.
    child: ChildGuard,
    directory: OwnedDirectory,
    pub(super) origin: String,
    pub(super) ca_file: PathBuf,
    client: reqwest::Client,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    origin: String,
    ca_file: PathBuf,
}

fn validated_ready(bytes: &[u8], directory: &Path) -> Option<(String, PathBuf)> {
    // A typed struct rejects duplicate keys as well as unknown fields.
    let ready: Ready = serde_json::from_slice(bytes).ok()?;
    let origin = ready.origin;
    let url = url::Url::parse(&origin).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != origin
    {
        return None;
    }
    (ready.ca_file == directory.join("ca.pem")).then_some((origin, ready.ca_file))
}

fn read_bounded_ca(path: &Path) -> std::io::Result<Vec<u8>> {
    const LIMIT: u64 = 64 * 1024;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > LIMIT {
        return Err(std::io::Error::other("invalid synthetic CA file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(std::io::Error::other("synthetic CA byte bound"));
    }
    Ok(bytes)
}

impl WalletFixture {
    pub(super) fn start(status: u16) -> Self {
        assert!(matches!(status, 200 | 503));
        let directory = OwnedDirectory::new();
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/didcomm_wallet_fixture.py");
        let python =
            std::env::var_os("MARTY_DIDCOMM_TEST_PYTHON").unwrap_or_else(|| "python3".into());
        let mut command = Command::new(python);
        command.env_clear();
        for key in ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("PYTHONUTF8", "1")
            .arg(script)
            .arg(&directory.0)
            .arg("--status")
            .arg(status.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ChildGuard(command.spawn().expect("start owned HTTPS wallet"));
        let stdout = child.0.stdout.take().expect("wallet readiness pipe");
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = BufReader::new(stdout.take(4097)).read_until(b'\n', &mut bytes);
            let valid = result.is_ok() && bytes.len() <= 4096 && bytes.ends_with(b"\n");
            let _ = sender.send(valid.then_some(bytes));
        });
        let ready = receiver.recv_timeout(Duration::from_secs(40));
        if ready.is_err() {
            let _ = child.0.kill();
            let _ = child.0.wait();
        }
        reader.join().expect("wallet readiness reader joined");
        let bytes = ready
            .expect("bounded wallet startup")
            .expect("wallet ready frame");
        let (origin, ca_file) = validated_ready(&bytes, &directory.0)
            .expect("wallet ready frame stays within owned fixture");
        let ca = reqwest::Certificate::from_pem(
            &read_bounded_ca(&ca_file).expect("read bounded synthetic wallet CA"),
        )
        .expect("parse synthetic wallet CA");
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .add_root_certificate(ca)
            .build()
            .expect("bounded capture client");
        Self {
            child,
            directory,
            origin,
            ca_file,
            client,
        }
    }

    pub(super) async fn captures(&self) -> Value {
        let mut response = self
            .client
            .get(format!("{}/captures", self.origin))
            .send()
            .await
            .expect("read synthetic wallet captures");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        // Four MiB raw capture limit, at most six JSON bytes per raw byte.
        const LIMIT: usize = 25 * 1024 * 1024;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.expect("bounded capture body") {
            assert!(
                bytes.len() + chunk.len() <= LIMIT,
                "wallet capture byte bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).expect("wallet capture JSON")
    }

    pub(super) fn close_verified(mut self) {
        self.child.0.kill().expect("stop exact-owned wallet child");
        self.child.0.wait().expect("reap exact-owned wallet child");
        let path = self.directory.0.clone();
        drop(self);
        assert!(!path.exists(), "owned wallet certificate cleanup");
    }
}

#[test]
fn wallet_readiness_rejects_external_or_ambiguous_resources() {
    let root = std::env::temp_dir().join("synthetic-wallet-ready-only");
    let good = serde_json::json!({
        "origin": "https://127.0.0.1:54321", "ca_file": root.join("ca.pem")
    });
    assert!(validated_ready(&serde_json::to_vec(&good).unwrap(), &root).is_some());
    for origin in [
        "http://127.0.0.1:54321",
        "https://example.com:54321",
        "https://127.0.0.1:0",
        "https://127.0.0.1",
        "https://user@127.0.0.1:54321",
        "https://127.0.0.1:54321/inbox",
        "https://127.0.0.1:54321?secret=x",
        "https://127.0.0.1:54321#fragment",
        "https://127.0.0.1:54321/",
    ] {
        let mut value = good.clone();
        value["origin"] = serde_json::json!(origin);
        assert!(validated_ready(&serde_json::to_vec(&value).unwrap(), &root).is_none());
    }
    let mut wrong_ca = good.clone();
    wrong_ca["ca_file"] = serde_json::json!(root.join("other.pem"));
    assert!(validated_ready(&serde_json::to_vec(&wrong_ca).unwrap(), &root).is_none());
    let mut extra = good;
    extra["unexpected"] = serde_json::json!(true);
    assert!(validated_ready(&serde_json::to_vec(&extra).unwrap(), &root).is_none());
    let duplicate = format!(
        "{{\"origin\":\"https://127.0.0.1:54321\",\"origin\":\"https://127.0.0.1:54321\",\"ca_file\":{}}}",
        serde_json::to_string(&root.join("ca.pem")).unwrap()
    );
    assert!(validated_ready(duplicate.as_bytes(), &root).is_none());
}

#[test]
fn wallet_ca_read_is_bounded_and_requires_a_regular_file() {
    let directory = OwnedDirectory::new();
    let path = directory.0.join("ca.pem");
    assert!(read_bounded_ca(&directory.0).is_err());
    assert!(read_bounded_ca(&path).is_err());
    std::fs::write(&path, b"synthetic").unwrap();
    assert_eq!(read_bounded_ca(&path).unwrap(), b"synthetic");
    std::fs::write(&path, vec![b'x'; 64 * 1024 + 1]).unwrap();
    assert!(read_bounded_ca(&path).is_err());
}

#[tokio::test]
async fn owned_wallet_starts_and_captures_over_verified_https() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Wallet subprocess test requires the explicit fixture gate");
        return;
    }
    let wallet = WalletFixture::start(200);
    let response = wallet
        .client
        .post(format!("{}/inbox", wallet.origin))
        .header("content-type", "application/didcomm-encrypted+json")
        .body("synthetic-wallet-startup-control")
        .send()
        .await
        .expect("verified TLS wallet startup control");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        wallet.captures().await,
        serde_json::json!({
            "messages":["synthetic-wallet-startup-control"], "failures":0
        })
    );
    wallet.close_verified();
}
