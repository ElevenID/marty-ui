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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutputDiagnostic {
    Quiet,
    SqlxSlowQueries,
    AuthenticationMaterial,
    TooLarge,
    Other,
    ReadFailure,
}

fn read_bounded(reader: &mut File) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.take(65_537).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn contains_authentication(bytes: &[u8], token: &str, database_url: &str) -> bool {
    let database = url::Url::parse(database_url).unwrap();
    let found = [
        token,
        "synthetic-process-signal-key",
        "synthetic-startup-api-key",
        "synthetic-startup-hmac-key",
        "synthetic-local-only",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ]
    .into_iter()
    .chain(database.password())
    .filter(|secret| !secret.is_empty())
    .any(|secret| {
        bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    });
    found
}

/// Classification is never acceptance: the strict empty-output gate remains.
/// No JSON field, SQL, path, panic payload or arbitrary target is returned.
fn classify(streams: &[Vec<u8>; 2], token: &str, database_url: &str) -> OutputDiagnostic {
    if streams.iter().any(|bytes| bytes.len() > 65_536) {
        return OutputDiagnostic::TooLarge;
    }
    if streams
        .iter()
        .any(|bytes| contains_authentication(bytes, token, database_url))
    {
        return OutputDiagnostic::AuthenticationMaterial;
    }
    if streams.iter().all(Vec::is_empty) {
        return OutputDiagnostic::Quiet;
    }
    for bytes in streams.iter().filter(|bytes| !bytes.is_empty()) {
        if !bytes.ends_with(b"\n") {
            return OutputDiagnostic::Other;
        }
        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) else {
                return OutputDiagnostic::Other;
            };
            if record["level"] != "WARN"
                || record["target"] != "sqlx::query"
                || record["fields"]["message"]
                    != "slow statement: execution time exceeded alert threshold"
            {
                return OutputDiagnostic::Other;
            }
        }
    }
    OutputDiagnostic::SqlxSlowQueries
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
        for (index, reader) in self.readers.iter_mut().enumerate() {
            let bytes = read_bounded(reader).unwrap();
            assert!(
                bytes.len() <= 65_536,
                "native worker output exceeded bounded capture"
            );
            assert!(
                !contains_authentication(&bytes, token, database_url),
                "native worker output contained synthetic authentication material"
            );
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

    pub(super) fn diagnostic(&mut self, token: &str, database_url: &str) -> OutputDiagnostic {
        let [stdout, stderr] = &mut self.readers;
        match (read_bounded(stdout), read_bounded(stderr)) {
            (Ok(stdout), Ok(stderr)) => classify(&[stdout, stderr], token, database_url),
            _ => OutputDiagnostic::ReadFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DATABASE: &str = "postgres://user:synthetic-db-password@127.0.0.1/output_test";

    fn slow_query() -> Vec<u8> {
        let record = serde_json::json!({"level":"WARN","target":"sqlx::query",
            "fields":{"message":"slow statement: execution time exceeded alert threshold",
                "db.statement":"synthetic SQL not forwarded"}});
        format!("{record}\n").into_bytes()
    }

    #[test]
    fn output_classification_is_closed_bounded_and_does_not_accept_logs() {
        assert_eq!(
            classify(&[vec![], vec![]], "token", DATABASE),
            OutputDiagnostic::Quiet
        );
        for stream in 0..2 {
            let mut streams = [vec![], vec![]];
            streams[stream] = slow_query();
            assert_eq!(
                classify(&streams, "token", DATABASE),
                OutputDiagnostic::SqlxSlowQueries
            );
            streams[stream].extend_from_slice(b"private arbitrary warning\n");
            assert_eq!(
                classify(&streams, "token", DATABASE),
                OutputDiagnostic::Other
            );
            streams[stream] = vec![b'x'; 65_537];
            assert_eq!(
                classify(&streams, "token", DATABASE),
                OutputDiagnostic::TooLarge
            );
            for secret in ["token", "synthetic-db-password", "synthetic-local-only"] {
                streams[stream] = format!("{secret}\n").into_bytes();
                assert_eq!(
                    classify(&streams, "token", DATABASE),
                    OutputDiagnostic::AuthenticationMaterial
                );
            }
        }
        for bytes in [
            b"{}\n".to_vec(),
            b"[]\n".to_vec(),
            b"\n".to_vec(),
            slow_query()[..slow_query().len() - 1].to_vec(),
            vec![0xff, b'\n'],
        ] {
            assert_eq!(
                classify(&[bytes, vec![]], "token", DATABASE),
                OutputDiagnostic::Other
            );
        }
        for (field, value) in [("level", "ERROR"), ("target", "sqlx::query-private")] {
            let mut record: serde_json::Value = serde_json::from_slice(&slow_query()).unwrap();
            record[field] = value.into();
            assert_eq!(
                classify(
                    &[format!("{record}\n").into_bytes(), vec![]],
                    "token",
                    DATABASE
                ),
                OutputDiagnostic::Other
            );
        }
    }
}
