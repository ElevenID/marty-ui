//! Failure-only output from synthetic, exact-owned containers. No output bytes
//! enter console errors; CI uploads only this separately provisioned directory.

use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(super) const STREAM_LIMIT: u64 = 2 * 1024 * 1024;
const DIRECTORY: &str = "marty-owned-runtime-diagnostics";
const MARKER: &str = ".owner";
const REFUSAL: &str = "Owned runtime diagnostic directory validation failed";

pub(super) struct Diagnostics {
    root: PathBuf,
    directory: PathBuf,
    owner: String,
}

fn no_links(path: &Path) -> Result<(), String> {
    for component in path.ancestors() {
        let metadata = component.symlink_metadata().map_err(|_| REFUSAL)?;
        if metadata.file_type().is_symlink() {
            return Err(REFUSAL.into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(REFUSAL.into());
            }
        }
    }
    Ok(())
}

impl Diagnostics {
    pub(super) fn from_environment() -> Result<Option<Self>, String> {
        match (
            std::env::var_os("MARTY_RUNTIME_DIAGNOSTICS"),
            std::env::var_os("MARTY_RUNTIME_DIAGNOSTICS_OWNER"),
        ) {
            (None, None) => Ok(None),
            (Some(directory), Some(owner)) => {
                let root = std::env::var_os("RUNNER_TEMP").ok_or(REFUSAL)?;
                let value = Self {
                    root: root.into(),
                    directory: directory.into(),
                    owner: owner.into_string().map_err(|_| REFUSAL)?,
                };
                value.validate()?;
                Ok(Some(value))
            }
            _ => Err(REFUSAL.into()),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let owner = Uuid::parse_str(&self.owner).map_err(|_| REFUSAL)?;
        if owner.get_version_num() != 4
            || owner.to_string() != self.owner
            || !self.root.is_absolute()
            || self.directory != self.root.join(DIRECTORY)
        {
            return Err(REFUSAL.into());
        }
        no_links(&self.root)?;
        no_links(&self.directory)?;
        let marker = self.directory.join(MARKER);
        no_links(&marker)?;
        let metadata = marker.symlink_metadata().map_err(|_| REFUSAL)?;
        if !metadata.is_file() || metadata.len() != 36 {
            return Err(REFUSAL.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let directory = self.directory.metadata().map_err(|_| REFUSAL)?;
            let root = self.root.metadata().map_err(|_| REFUSAL)?;
            if metadata.nlink() != 1
                || directory.uid() != root.uid()
                || metadata.uid() != root.uid()
                || directory.mode() & 0o077 != 0
            {
                return Err(REFUSAL.into());
            }
        }
        if fs::read(marker).map_err(|_| REFUSAL)? != self.owner.as_bytes() {
            return Err(REFUSAL.into());
        }
        Ok(())
    }

    fn record(&self, id: &str, status: &Value, stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
        self.validate()?;
        if id.len() != 64
            || !id
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
            || stdout.len() as u64 > STREAM_LIMIT
            || stderr.len() as u64 > STREAM_LIMIT
        {
            return Err("Owned runtime diagnostic identity/output bound failed".into());
        }
        let metadata = serde_json::to_vec(&json!({
            "schema": 1,
            "container_id": id,
            "exit_code": status["State"]["ExitCode"].as_i64(),
            "stdout_bytes": stdout.len(),
            "stderr_bytes": stderr.len(),
        }))
        .map_err(|_| "Owned runtime diagnostic metadata failed")?;
        for (suffix, bytes) in [
            ("stdout.log", stdout),
            ("stderr.log", stderr),
            ("json", metadata.as_slice()),
        ] {
            // Exclusive creation refuses existing files, hardlinks and symlinks.
            self.validate()?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(self.directory.join(format!("{id}.{suffix}")))
                .map_err(|_| "Owned runtime diagnostic file creation failed")?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| "Owned runtime diagnostic write failed")?;
        }
        Ok(())
    }
}

pub(super) fn record_failure(
    result: Result<(), String>,
    diagnostics: Option<&Diagnostics>,
    id: &str,
    status: &Value,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), String> {
    if result.is_ok() {
        return result;
    }
    let recorded = diagnostics.map_or(Ok(()), |v| v.record(id, status, stdout, stderr));
    super::base_runtime_container::retain_failure(result, recorded)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot(PathBuf);
    impl Drop for TestRoot {
        fn drop(&mut self) {
            // Exact newly created fixture only; never accept caller directories.
            let parent = std::env::temp_dir().canonicalize().unwrap();
            assert_eq!(self.0.parent(), Some(parent.as_path()));
            assert!(self
                .0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("marty-diagnostic-test-"));
            assert!(!self.0.symlink_metadata().unwrap().file_type().is_symlink());
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn fixture() -> (TestRoot, Diagnostics) {
        let root_path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("marty-diagnostic-test-{}", Uuid::new_v4()));
        fs::create_dir(&root_path).unwrap();
        let root = TestRoot(root_path.clone());
        let directory = root_path.join(DIRECTORY);
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = Uuid::new_v4().to_string();
        fs::write(directory.join(MARKER), &owner).unwrap();
        (
            root,
            Diagnostics {
                root: root_path,
                directory,
                owner,
            },
        )
    }

    #[test]
    fn failure_preserves_both_streams_without_exposing_bytes_or_waiving_failure() {
        let (_root, diagnostics) = fixture();
        let id = "a".repeat(64);
        let state = json!({"State":{"Running":false,"ExitCode":101}});
        let result = record_failure(
            Err("child failed".into()),
            Some(&diagnostics),
            &id,
            &state,
            b"stdout\0\xff",
            b"private-panic-canary",
        );
        assert_eq!(result, Err("child failed".into()));
        assert_eq!(
            fs::read(diagnostics.directory.join(format!("{id}.stdout.log"))).unwrap(),
            b"stdout\0\xff"
        );
        assert_eq!(
            fs::read(diagnostics.directory.join(format!("{id}.stderr.log"))).unwrap(),
            b"private-panic-canary"
        );
        let metadata: Value = serde_json::from_slice(
            &fs::read(diagnostics.directory.join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata,
            json!({"schema":1,"container_id":id,"exit_code":101,"stdout_bytes":8,"stderr_bytes":20})
        );
        let duplicate = record_failure(
            Err("child failed".into()),
            Some(&diagnostics),
            &id,
            &state,
            b"replacement",
            b"",
        );
        assert_eq!(
            duplicate,
            Err("child failed; additionally: Owned runtime diagnostic file creation failed".into())
        );
        assert_eq!(
            fs::read(diagnostics.directory.join(format!("{id}.stdout.log"))).unwrap(),
            b"stdout\0\xff"
        );
    }

    #[test]
    fn success_writes_nothing_and_oversize_or_unowned_targets_are_rejected() {
        let (_root, mut diagnostics) = fixture();
        let id = "b".repeat(64);
        assert_eq!(
            record_failure(Ok(()), Some(&diagnostics), &id, &Value::Null, b"", b""),
            Ok(())
        );
        assert_eq!(fs::read_dir(&diagnostics.directory).unwrap().count(), 1);
        for (stdout, stderr) in [
            (vec![0; STREAM_LIMIT as usize + 1], vec![]),
            (vec![], vec![0; STREAM_LIMIT as usize + 1]),
        ] {
            assert!(diagnostics
                .record(&id, &Value::Null, &stdout, &stderr)
                .is_err());
        }
        assert!(diagnostics
            .record("../unowned", &Value::Null, b"", b"")
            .is_err());
        diagnostics.owner = Uuid::new_v4().to_string();
        assert!(diagnostics.validate().is_err());
        diagnostics.directory = diagnostics.root.clone();
        assert!(diagnostics.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_directory_marker_and_output_are_refused() {
        use std::os::unix::fs::symlink;
        let (_root, diagnostics) = fixture();
        let marker = diagnostics.directory.join(MARKER);
        let original = diagnostics.root.join("original-owner");
        fs::rename(&marker, &original).unwrap();
        symlink(&original, &marker).unwrap();
        assert!(diagnostics.validate().is_err());
        fs::remove_file(&marker).unwrap();
        fs::rename(original, &marker).unwrap();
        let hardlink = diagnostics.root.join("linked-owner");
        fs::hard_link(&marker, &hardlink).unwrap();
        assert!(diagnostics.validate().is_err());
        fs::remove_file(hardlink).unwrap();
        diagnostics.validate().unwrap();
        let id = "c".repeat(64);
        symlink(
            &marker,
            diagnostics.directory.join(format!("{id}.stdout.log")),
        )
        .unwrap();
        assert!(diagnostics.record(&id, &Value::Null, b"", b"").is_err());
        let directory = diagnostics.root.join("original-directory");
        fs::rename(&diagnostics.directory, &directory).unwrap();
        symlink(&directory, &diagnostics.directory).unwrap();
        assert!(diagnostics.validate().is_err());
    }
}
