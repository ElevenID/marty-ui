//! Immutable beta runtime inputs survive removal of the source worktree.
//! This operation stages files only; it never deploys or authorizes recovery.
use crate::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

const SOURCES: &[&str] = &[
    "docker/init-databases.sh",
    "config/keycloak",
    "scripts/setup-keycloak.sh",
    "docker/openbao-selfhost.hcl",
    "docker/openbao-init.sh",
    "docker/openbao-selfhost-init.sh",
    "docker/openbao-haip-workload-policy.hcl",
    "config/envoy/envoy.yaml",
    "config/envoy/proto_descriptor.pb",
    "docker/canvas-localhost-bridge/Cargo.toml",
    "docker/canvas-localhost-bridge/Cargo.lock",
    "docker/canvas-localhost-bridge/Dockerfile",
    "docker/canvas-localhost-bridge/src/main.rs",
    "config/canvas/production-local.rb",
    "config/canvas/dynamic_settings.local.yml",
    "config/canvas/session_store.local.yml",
    "docker/waltid/wallet-api/config",
    "docker/waltid/nginx.conf",
    "nginx-tunnel.conf.template",
    "scripts/nginx-entrypoint.sh",
];
const REFUSAL: &str = "Beta runtime configuration staging failed";
const CONFLICT: &str = "Durable runtime configuration conflicts with content-addressed revision";
const MANIFEST: &str = "runtime-config-manifest.json";

fn ordinary(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| REFUSAL.to_owned())?;
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
    Ok(metadata)
}

fn collect(root: &Path, relative: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    let path = root.join(relative);
    let metadata = ordinary(&path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(&path).map_err(|_| REFUSAL)? {
            let entry = entry.map_err(|_| REFUSAL)?;
            collect(root, &relative.join(entry.file_name()), files)?;
        }
    } else if metadata.is_file() && metadata.len() <= 128 * 1024 * 1024 {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000).share_mode(1);
        }
        let file = options.open(&path).map_err(|_| REFUSAL)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if file.metadata().map_err(|_| REFUSAL)?.file_attributes() & 0x400 != 0 {
                return Err(REFUSAL.into());
            }
        }
        if !path.canonicalize().map_err(|_| REFUSAL)?.starts_with(root) {
            return Err(REFUSAL.into());
        }
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSAL)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(REFUSAL.into());
        }
        let name = relative.to_str().ok_or(REFUSAL)?.replace('\\', "/");
        files.insert(name, bytes);
    } else {
        return Err(REFUSAL.into());
    }
    Ok(())
}

fn manifest(revision: &str, files: &BTreeMap<String, Vec<u8>>) -> Value {
    json!({"schema_version":1,"marty_ui_revision":revision,"files":files.iter().map(|(name,bytes)|
        json!({"path":name,"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))})).collect::<Vec<_>>()})
}

fn verify_existing(path: &Path, expected: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if !ordinary(path)?.is_dir() {
        return Err(CONFLICT.into());
    }
    ordinary(&path.join(MANIFEST))?;
    let mut observed: Value =
        serde_json::from_slice(&fs::read(path.join(MANIFEST)).map_err(|_| CONFLICT)?)
            .map_err(|_| CONFLICT)?;
    // Accept the historical PowerShell JSON serialization/order, but verify bytes
    // rather than trusting a manifest next to possibly changed runtime inputs.
    let mut observed_files = BTreeMap::new();
    collect(path, Path::new(""), &mut observed_files)?;
    observed_files.remove(MANIFEST);
    let mut expected = expected.clone();
    normalize_manifest(&mut observed)?;
    normalize_manifest(&mut expected)?;
    if observed != expected || observed_files != *files {
        return Err(CONFLICT.into());
    }
    Ok(())
}

fn normalize_manifest(value: &mut Value) -> Result<()> {
    let entries = value["files"].as_array_mut().ok_or(CONFLICT)?;
    if entries.iter().any(|entry| !entry["path"].is_string()) {
        return Err(CONFLICT.into());
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if entries
        .windows(2)
        .any(|pair| pair[0]["path"] == pair[1]["path"])
    {
        return Err(CONFLICT.into());
    }
    Ok(())
}

fn stage_at(repo: &Path, durable: &Path, revision: &str, sources: &[&str]) -> Result<PathBuf> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Beta runtime configuration requires a full source revision".into());
    }
    let repo = repo.canonicalize().map_err(|_| REFUSAL)?;
    let mut files = BTreeMap::new();
    for source in sources {
        let relative = Path::new(source);
        // Every component must stay within the source tree; do not traverse links.
        let mut checked = repo.clone();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(REFUSAL.into());
            };
            checked.push(name);
            ordinary(&checked)?;
        }
        collect(&repo, relative, &mut files)?;
    }
    // Inspect each existing ancestor before creating the next component.
    let mut checked = PathBuf::new();
    for component in durable.components() {
        checked.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(_) => {
                if !ordinary(&checked)?.is_dir() {
                    return Err(REFUSAL.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&checked).map_err(|_| REFUSAL)?;
                if !ordinary(&checked)?.is_dir() {
                    return Err(REFUSAL.into());
                }
            }
            Err(_) => return Err(REFUSAL.into()),
        }
    }
    let durable = durable.canonicalize().map_err(|_| REFUSAL)?;
    let destination = durable.join(revision);
    let expected = manifest(revision, &files);
    if fs::symlink_metadata(&destination).is_ok() {
        verify_existing(&destination, &expected, &files)?;
        return Ok(destination);
    }
    let staging = tempfile::Builder::new()
        .prefix(&format!("{revision}.staging."))
        .tempdir_in(&durable)
        .map_err(|_| REFUSAL)?;
    for (name, bytes) in &files {
        let path = staging.path().join(name);
        fs::create_dir_all(path.parent().ok_or(REFUSAL)?).map_err(|_| REFUSAL)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| REFUSAL)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| REFUSAL)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging.path().join(MANIFEST))
        .map_err(|_| REFUSAL)?;
    serde_json::to_writer_pretty(&mut file, &expected).map_err(|_| REFUSAL)?;
    file.write_all(b"\n")
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSAL)?;
    drop(file);
    // Claim the generation without replacing any existing entry. The manifest
    // is installed last; readers refuse an interrupted unpublished generation.
    if let Err(error) = fs::create_dir(&destination) {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            verify_existing(&destination, &expected, &files)?;
            return Ok(destination);
        }
        return Err(REFUSAL.into());
    }
    for name in files
        .keys()
        .map(String::as_str)
        .chain(std::iter::once(MANIFEST))
    {
        let path = destination.join(name);
        fs::create_dir_all(path.parent().ok_or(REFUSAL)?).map_err(|_| REFUSAL)?;
        let bytes = fs::read(staging.path().join(name)).map_err(|_| REFUSAL)?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(path)
            .map_err(|_| "Beta runtime configuration publication is incomplete; preserve generation for inspection")?;
        output.write_all(&bytes).and_then(|_|output.sync_all())
            .map_err(|_| "Beta runtime configuration publication is incomplete; preserve generation for inspection")?;
    }

    Ok(destination)
}

pub fn stage(repo: &Path, revision: &str) -> Result<Value> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .map_err(|_| REFUSAL)?;
    if !output.status.success() {
        return Err(REFUSAL.into());
    }
    let common = PathBuf::from(
        String::from_utf8(output.stdout)
            .map_err(|_| REFUSAL)?
            .trim(),
    );
    let primary = common.parent().ok_or(REFUSAL)?;
    let destination = stage_at(
        repo,
        &primary.join("tests/artifacts/runtime-config"),
        revision,
        SOURCES,
    )?;
    Ok(json!({"root":destination,"manifest":destination.join(MANIFEST)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    #[test]
    fn historical_manifest_format_and_order_are_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("A"), b"first").unwrap();
        fs::write(repo.join("b"), b"second").unwrap();
        let durable = temp.path().join("durable");
        let output = stage_at(&repo, &durable, REVISION, &["A", "b"]).unwrap();
        let mut old: Value =
            serde_json::from_slice(&fs::read(output.join(MANIFEST)).unwrap()).unwrap();
        old["files"].as_array_mut().unwrap().reverse();
        let historical = serde_json::to_string_pretty(&old)
            .unwrap()
            .replace('\n', "\r\n");
        fs::write(output.join(MANIFEST), historical.as_bytes()).unwrap();
        assert_eq!(
            stage_at(&repo, &durable, REVISION, &["A", "b"]).unwrap(),
            output
        );
        assert_eq!(
            fs::read(output.join(MANIFEST)).unwrap(),
            historical.as_bytes()
        );
    }

    #[test]
    fn concurrent_publishers_never_replace_or_modify_an_existing_generation() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("input"), vec![7; 1024 * 1024]).unwrap();
        let durable = temp.path().join("durable");
        fs::create_dir(&durable).unwrap();
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| stage_at(&repo, &durable, REVISION, &["input"]));
            let b = scope.spawn(|| stage_at(&repo, &durable, REVISION, &["input"]));
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert!(results.iter().any(Result::is_ok));
        let output = stage_at(&repo, &durable, REVISION, &["input"]).unwrap();
        assert_eq!(
            fs::read(output.join("input")).unwrap(),
            vec![7; 1024 * 1024]
        );
        assert_eq!(fs::read_dir(durable).unwrap().count(), 1);
    }

    #[test]
    fn incomplete_claim_is_preserved_and_blocks_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("input"), b"expected").unwrap();
        let durable = temp.path().join("durable");
        let claimed = durable.join(REVISION);
        fs::create_dir_all(&claimed).unwrap();
        fs::write(claimed.join("input"), b"unfinished").unwrap();
        assert!(stage_at(&repo, &durable, REVISION, &["input"]).is_err());
        assert_eq!(fs::read(claimed.join("input")).unwrap(), b"unfinished");
        assert!(!claimed.join(MANIFEST).exists());
    }

    #[cfg(unix)]
    #[test]
    fn redirected_destination_parent_is_rejected_without_writes() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("input"), b"expected").unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("redirect")).unwrap();
        assert!(stage_at(
            &repo,
            &temp.path().join("redirect/durable"),
            REVISION,
            &["input"]
        )
        .is_err());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }
    #[test]
    fn immutable_snapshot_reuses_equal_content_and_preserves_changed_existing_files() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("config")).unwrap();
        fs::write(repo.join("config/input"), b"runtime\0bytes\r\n").unwrap();
        let durable = temp.path().join("durable");
        let output = stage_at(&repo, &durable, REVISION, &["config"]).unwrap();
        assert_eq!(
            stage_at(&repo, &durable, REVISION, &["config"]).unwrap(),
            output
        );
        fs::write(output.join("config/input"), b"user change").unwrap();
        assert!(stage_at(&repo, &durable, REVISION, &["config"]).is_err());
        assert_eq!(
            fs::read(output.join("config/input")).unwrap(),
            b"user change"
        );
        assert_eq!(fs::read_dir(durable).unwrap().count(), 1);
    }
    #[test]
    fn missing_or_invalid_inputs_publish_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let durable = temp.path().join("durable");
        assert!(stage_at(temp.path(), &durable, "../escape", &["missing"]).is_err());
        assert!(stage_at(temp.path(), &durable, REVISION, &["missing"]).is_err());
        assert!(!durable.exists());
    }
    #[cfg(unix)]
    #[test]
    fn linked_source_cannot_import_external_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("repo");
        fs::create_dir(&source).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"private").unwrap();
        std::os::unix::fs::symlink(outside, source.join("input")).unwrap();
        assert!(stage_at(&source, &temp.path().join("durable"), REVISION, &["input"]).is_err());
    }
}
