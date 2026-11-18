//! Validate already authenticated extraction before any runtime preparation.
//! Caller holds exclusive ownership of private staging and preserves these bytes
//! through use. The package marker hashes contents, not permissions: executable
//! bits must originate from the authenticated archive via installer_artifacts.
//! This does not qualify Compose behavior, resource ownership, or readiness.
#![cfg(target_os = "linux")]

use crate::installer_release::{self, Inventory};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub type Result<T> = std::result::Result<T, String>;
const MARKER: &str = ".marty-selfhost-bundle.json";
const LOCK: &str = ".marty-selfhost-images.json";
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 16384;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn unique_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct UniqueMap;
    impl<'de> Visitor<'de> for UniqueMap {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("unique string map")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate bundle field"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(UniqueMap)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    #[serde(deserialize_with = "unique_map")]
    files: BTreeMap<String, String>,
    directories: Vec<String>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ImageLock {
    schema: String,
    release: String,
    #[serde(deserialize_with = "unique_map")]
    services: BTreeMap<String, String>,
    openbao_didcomm_image: String,
}
#[derive(Debug, Serialize)]
pub struct ValidatedBundle {
    pub schema: &'static str,
    pub file_count: usize,
    pub directory_count: usize,
    pub marker_sha256: String,
    pub image_lock_sha256: String,
    pub runtime_observed: bool,
}
fn valid_path(path: &str, root: bool) -> bool {
    (root && path.is_empty())
        || (!path.is_empty()
            && path.len() <= 1024
            && path.is_ascii()
            && path.split('/').count() <= 32
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.len() <= 255
                    && !part.ends_with(['.', ' '])
                    && part
                        .bytes()
                        .all(|b| (33..=126).contains(&b) && b != b'\\' && b != b':')
            }))
}
fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "bundle file unavailable")?;
    let m = file
        .metadata()
        .map_err(|_| "bundle file metadata unavailable")?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && matches!(m.mode() & 0o7777, 0o644 | 0o755)
            && m.len() <= MAX_FILE,
        "bundle file ownership/type/mode differs",
    )?;
    Ok(file)
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = regular(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read bundle metadata")?;
    require(bytes.len() as u64 <= limit, "bundle metadata exceeds limit")?;
    Ok(bytes)
}
struct Observed {
    files: BTreeMap<String, String>,
    directories: BTreeSet<String>,
    total: u64,
    entries: usize,
    folded: BTreeSet<String>,
}
impl Observed {
    fn visit(&mut self, root: &Path, path: &Path) -> Result<()> {
        self.entries += 1;
        require(
            self.entries <= MAX_ENTRIES,
            "bundle entry count exceeds limit",
        )?;
        let name = path
            .strip_prefix(root)
            .map_err(|_| "bundle path escapes root")?
            .to_str()
            .ok_or("bundle path is not UTF-8")?
            .to_owned();
        require(
            valid_path(&name, true) && self.folded.insert(name.to_ascii_lowercase()),
            "bundle path invalid or case-colliding",
        )?;
        let metadata = fs::symlink_metadata(path).map_err(|_| "bundle entry unavailable")?;
        require(
            !metadata.file_type().is_symlink() && metadata.uid() == unsafe { libc::geteuid() },
            "bundle entry linked or foreign",
        )?;
        if metadata.is_dir() {
            require(
                metadata.mode() & 0o7777 == 0o755,
                "bundle directory mode differs",
            )?;
            self.directories.insert(name);
            for entry in fs::read_dir(path).map_err(|_| "cannot enumerate bundle")? {
                self.visit(
                    root,
                    &entry.map_err(|_| "cannot inspect bundle entry")?.path(),
                )?;
            }
        } else {
            require(metadata.is_file(), "special bundle file refused")?;
            let mut file = regular(path)?;
            let before = file
                .metadata()
                .map_err(|_| "bundle file metadata unavailable")?;
            self.total = self
                .total
                .checked_add(before.len())
                .ok_or("bundle size overflow")?;
            require(
                self.total <= MAX_TOTAL,
                "bundle expanded size exceeds limit",
            )?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|_| "cannot hash bundle file")?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                require(
                    size <= MAX_FILE && size <= before.len(),
                    "bundle file changed or exceeds bound",
                )?;
                hasher.update(&buffer[..n]);
            }
            require(size == before.len(), "bundle file changed")?;
            self.files.insert(name, format!("{:x}", hasher.finalize()));
        }
        Ok(())
    }
}

pub fn validate_bundle(
    root: &Path,
    inventory: &Inventory,
    external_image_lock_bytes: &[u8],
) -> Result<ValidatedBundle> {
    crate::installer_runtime::private_parent(root.parent().ok_or("bundle parent missing")?)?;
    require(
        root.is_absolute() && root.canonicalize().map_err(|_| "bundle root unavailable")? == root,
        "bundle root is not canonical",
    )?;
    require(
        root.file_name().and_then(|v| v.to_str()) == Some("selfhost-prepared"),
        "bundle root differs",
    )?;
    let lock_entry = inventory.artifact("prepared-selfhost-images.json")?;
    require(
        external_image_lock_bytes.len() <= 65536
            && external_image_lock_bytes.len() as u64 == lock_entry.size
            && installer_release::sha256(external_image_lock_bytes) == lock_entry.sha256,
        "external image lock differs from inventory",
    )?;
    let external: ImageLock = serde_json::from_slice(external_image_lock_bytes)
        .map_err(|_| "invalid external image lock")?;
    require(
        external.schema == "marty.selfhost-image-lock/v1"
            && external.release
                == format!(
                    "marty-ui@{}",
                    inventory
                        .release_tag
                        .strip_prefix('v')
                        .ok_or("invalid inventory release")?
                ),
        "image lock identity differs",
    )?;
    installer_release::release_tier(&inventory.release_tag)?;
    require(
        !external.services.is_empty() && !external.services.contains_key("openbao_didcomm_image"),
        "invalid image service roles",
    )?;
    let mut expected = external.services.clone();
    expected.insert(
        "openbao_didcomm_image".into(),
        external.openbao_didcomm_image.clone(),
    );
    require(
        expected == inventory.images,
        "image lock roles/digests differ from inventory",
    )?;
    let marker_bytes = read(&root.join(MARKER), 4 * 1024 * 1024)?;
    let marker: Marker =
        serde_json::from_slice(&marker_bytes).map_err(|_| "invalid or ambiguous bundle marker")?;
    require(
        marker.schema == "marty.selfhost-bundle-files/v1"
            && !marker.files.is_empty()
            && !marker.files.contains_key(MARKER),
        "bundle marker identity differs",
    )?;
    for (name, hash) in &marker.files {
        require(
            valid_path(name, false)
                && hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid marker file binding",
        )?;
    }
    let directories: BTreeSet<_> = marker.directories.iter().cloned().collect();
    require(
        directories.len() == marker.directories.len()
            && directories.contains("")
            && directories.iter().all(|p| valid_path(p, true)),
        "invalid marker directories",
    )?;
    let mut observed = Observed {
        files: BTreeMap::new(),
        directories: BTreeSet::new(),
        total: 0,
        entries: 0,
        folded: BTreeSet::new(),
    };
    observed.visit(root, root)?;
    let marker_sha = installer_release::sha256(&marker_bytes);
    require(
        observed.files.remove(MARKER).as_deref() == Some(marker_sha.as_str()),
        "marker changed during validation",
    )?;
    require(
        observed.files == marker.files && observed.directories == directories,
        "bundle inventory or file contents differ from marker",
    )?;
    let embedded_bytes = read(&root.join(LOCK), 65536)?;
    require(
        observed.files.get(LOCK) == Some(&installer_release::sha256(&embedded_bytes)),
        "embedded lock changed during validation",
    )?;
    let embedded: ImageLock =
        serde_json::from_slice(&embedded_bytes).map_err(|_| "invalid embedded image lock")?;
    require(
        embedded == external,
        "embedded image lock differs from external lock",
    )?;
    require(
        observed.files.contains_key("docker-compose.yml"),
        "rendered Compose file missing",
    )?;
    Ok(ValidatedBundle {
        schema: "elevenid.installer-bundle-validation/v1",
        file_count: observed.files.len() + 1,
        directory_count: observed.directories.len(),
        marker_sha256: marker_sha,
        image_lock_sha256: installer_release::sha256(external_image_lock_bytes),
        runtime_observed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn write(root: &Path, name: &str, bytes: &[u8], mode: u32) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Inventory, Vec<u8>) {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.path().join("selfhost-prepared");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let lock = json!({"schema":"marty.selfhost-image-lock/v1","release":"marty-ui@1.2.3",
          "services":{"app":format!("ghcr.io/elevenid/app@sha256:{}","a".repeat(64))},
          "openbao_didcomm_image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}","b".repeat(64))});
        let lock_bytes = serde_json::to_vec(&lock).unwrap();
        write(&root, LOCK, &lock_bytes, 0o644);
        write(&root, "docker-compose.yml", b"services: {}\n", 0o644);
        write(&root, "scripts/start.sh", b"#!/bin/sh\nexit 0\n", 0o755);
        fs::set_permissions(root.join("scripts"), fs::Permissions::from_mode(0o755)).unwrap();
        let files: BTreeMap<_, _> = [LOCK, "docker-compose.yml", "scripts/start.sh"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    installer_release::sha256(&fs::read(root.join(name)).unwrap()),
                )
            })
            .collect();
        let marker = json!({"schema":"marty.selfhost-bundle-files/v1","files":files,"directories":["","scripts"]});
        write(&root, MARKER, &serde_json::to_vec(&marker).unwrap(), 0o644);
        let artifacts:Vec<_>=["install.sh","marty-deploy-linux-amd64","prepared-selfhost-bundle.zip","prepared-selfhost-images.json"].into_iter()
          .map(|name|if name=="prepared-selfhost-images.json" {json!({"name":name,"sha256":installer_release::sha256(&lock_bytes),"size":lock_bytes.len()})}
                    else {json!({"name":name,"sha256":"a".repeat(64),"size":1})}).collect();
        let inv = json!({"schema":"elevenid.installer-inventory/v1","repository":installer_release::REPOSITORY,
          "source_sha":"a".repeat(40),"release_tag":"v1.2.3","platform":"linux/amd64","build_run_id":42,"build_run_attempt":1,
          "artifacts":artifacts,"images":{"app":lock["services"]["app"],"openbao_didcomm_image":lock["openbao_didcomm_image"]}});
        (
            parent,
            root,
            installer_release::parse_inventory(&serde_json::to_vec(&inv).unwrap()).unwrap(),
            lock_bytes,
        )
    }
    #[test]
    fn exact_marker_complete_inventory_and_image_binding_pass() {
        let (_owned, root, inv, lock) = fixture();
        let result = validate_bundle(&root, &inv, &lock).unwrap();
        assert_eq!(result.file_count, 4);
        assert_eq!(result.directory_count, 2);
        assert!(!result.runtime_observed);
        assert!(serde_json::to_value(result).is_ok());
    }
    #[test]
    fn validates_actual_production_packager_and_extractor_output() {
        use marty_selfhost_bundle::{package_with_image_lock, Options};
        let (owned, _fixture_root, inv, lock) = fixture();
        let source = owned.path().join("source");
        fs::create_dir(&source).unwrap();
        for name in [
            "docker-compose.selfhost.prod.yml",
            "docker-compose.selfhost.bundle.override.yml",
        ] {
            write(&source, name, b"services: {}\n", 0o644);
        }
        write(
            &source,
            ".env.selfhost.production.example",
            b"COMPOSE_PROJECT_NAME=fixture\n",
            0o644,
        );
        write(
            &source,
            "SELFHOST_BUNDLE.md",
            b"Self-host fixture.\n",
            0o644,
        );
        write(&source, "scripts/start.sh", b"#!/bin/sh\nexit 0\n", 0o755);
        write(
            &source,
            "release/stack-lock.json",
            br#"{"release":"marty-ui@1.2.3"}"#,
            0o644,
        );
        let manifest = json!({"assets":["docker-compose.selfhost.prod.yml",
            "docker-compose.selfhost.bundle.override.yml", ".env.selfhost.production.example",
            "SELFHOST_BUNDLE.md", "scripts"]});
        write(
            &source,
            "deploy-config/bundles/selfhost.json",
            &serde_json::to_vec(&manifest).unwrap(),
            0o644,
        );
        let lock_path = owned.path().join("external-images.json");
        fs::write(&lock_path, &lock).unwrap();
        let options = Options {
            repo: source,
            output: owned.path().join("packaged/selfhost-prepared"),
            archive: Some(owned.path().join("prepared.zip")),
            replace: false,
        };
        let published = package_with_image_lock(
            &options,
            |_, _| Ok("services:\n  app:\n    image: example:v1\n".into()),
            &lock_path,
        )
        .unwrap();
        let archive = published.archive.unwrap();
        let archive_hash = installer_release::sha256(&fs::read(&archive).unwrap());
        let extracted = crate::installer_artifacts::extract_bundle(
            &archive,
            &owned.path().join("extracted"),
            &archive_hash,
        )
        .unwrap();
        let report = validate_bundle(&extracted, &inv, &lock).unwrap();
        assert!(report.file_count >= 5);
        assert_eq!(report.image_lock_sha256, installer_release::sha256(&lock));
        assert!(!report.runtime_observed);
    }
    #[test]
    fn refuses_modified_executable_extra_file_directory_and_missing_file() {
        for mutation in ["script", "extra-file", "extra-dir", "missing"] {
            let (_owned, root, inv, lock) = fixture();
            match mutation {
                "script" => fs::write(root.join("scripts/start.sh"), b"changed").unwrap(),
                "extra-file" => write(&root, "unrecorded", b"x", 0o644),
                "extra-dir" => fs::create_dir(root.join("unrecorded")).unwrap(),
                _ => fs::remove_file(root.join("scripts/start.sh")).unwrap(),
            }
            assert!(
                validate_bundle(&root, &inv, &lock).is_err(),
                "accepted {mutation}"
            );
        }
    }
    #[test]
    fn refuses_links_and_public_writable_modes() {
        for mutation in ["symlink", "hardlink", "file-mode", "dir-mode"] {
            let (owned, root, inv, lock) = fixture();
            let path = root.join("scripts/start.sh");
            match mutation {
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    symlink("/etc/passwd", &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, owned.path().join("outside")).unwrap(),
                "file-mode" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap()
                }
                _ => fs::set_permissions(root.join("scripts"), fs::Permissions::from_mode(0o777))
                    .unwrap(),
            }
            assert!(validate_bundle(&root, &inv, &lock).is_err());
        }
    }
    #[test]
    fn rejects_duplicate_marker_unknown_fields_and_image_mismatches() {
        let (_owned, root, mut inv, lock) = fixture();
        let original = fs::read_to_string(root.join(MARKER)).unwrap();
        for raw in [
            original.replacen('{', "{\"schema\":\"duplicate\",", 1),
            original.replacen('{', "{\"extra\":true,", 1),
            original.replace("\"files\":{", "\"files\":{\"docker-compose.yml\":\"bad\","),
        ] {
            fs::write(root.join(MARKER), raw).unwrap();
            assert!(validate_bundle(&root, &inv, &lock).is_err());
        }
        fs::write(root.join(MARKER), original).unwrap();
        let mut other = lock.clone();
        other.push(b' ');
        assert!(validate_bundle(&root, &inv, &other).is_err());
        inv.images.insert(
            "app".into(),
            format!("ghcr.io/elevenid/app@sha256:{}", "f".repeat(64)),
        );
        assert!(validate_bundle(&root, &inv, &lock).is_err());
        let duplicate = String::from_utf8(lock)
            .unwrap()
            .replace("\"services\":{", "\"services\":{\"app\":\"bad\",");
        assert!(serde_json::from_str::<ImageLock>(&duplicate).is_err());
    }
    #[test]
    fn rejects_duplicate_or_unaccounted_marker_directories() {
        for directories in [
            json!(["", "scripts", "scripts"]),
            json!(["", "scripts", "absent"]),
        ] {
            let (_owned, root, inv, lock) = fixture();
            let mut marker: Value =
                serde_json::from_slice(&fs::read(root.join(MARKER)).unwrap()).unwrap();
            marker["directories"] = directories;
            fs::write(root.join(MARKER), serde_json::to_vec(&marker).unwrap()).unwrap();
            assert!(validate_bundle(&root, &inv, &lock).is_err());
        }
    }
}
