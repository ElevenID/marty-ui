//! Owned, bounded native worker output; independent readers never share child offsets.
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::Stdio,
};

pub(super) struct OwnedOutput {
    readers: [File; 2],
}

impl OwnedOutput {
    pub(super) fn new(control: &Path) -> (Self, Stdio, Stdio) {
        // The parent's protocol directory contains markers only. Its separately
        // owned root removes this sibling after all child handles have closed.
        let directory = control.parent().unwrap().join("native-worker-output");
        std::fs::create_dir(&directory).unwrap();
        let open = |name: &str| {
            let path = directory.join(name);
            let writer = OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let reader = File::open(path).unwrap();
            (writer, reader)
        };
        let (stdout, stdout_reader) = open("worker-stdout.log");
        let (stderr, stderr_reader) = open("worker-stderr.log");
        (
            Self {
                readers: [stdout_reader, stderr_reader],
            },
            Stdio::from(stdout),
            Stdio::from(stderr),
        )
    }

    pub(super) fn assert_private_quiet(&mut self, token: &str, database_url: &str) {
        let database = url::Url::parse(database_url).unwrap();
        let mut forbidden = vec![
            token,
            "synthetic-process-signal-key",
            "synthetic-startup-api-key",
            "synthetic-startup-hmac-key",
            "synthetic-local-only",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ];
        if let Some(password) = database.password() {
            forbidden.push(password);
        }
        for (index, reader) in self.readers.iter_mut().enumerate() {
            reader.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            reader.take(65_537).read_to_end(&mut bytes).unwrap();
            assert!(
                bytes.len() <= 65_536,
                "native worker output exceeded bounded capture"
            );
            for secret in forbidden.iter().filter(|secret| !secret.is_empty()) {
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes()),
                    "native worker output contained synthetic authentication material"
                );
            }
            // Python's two unrelated API-import warnings are explicitly not
            // manufactured here. At native WARN level any observed output must
            // be reviewed; expose only fixed stream index and byte count.
            assert!(
                bytes.is_empty(),
                "native worker output stream={index} bytes={}",
                bytes.len()
            );
        }
    }
}
