//! Optional connector acquisition uses the core release's exact signer/run and
//! persists its authenticated bytes before any runtime mutation. Later reads
//! require the journal-bound receipt, the original proofs and the exact closed
//! payload; a local manifest alone never grants image or Compose authority.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{BoundFile, ComposeInputs},
    installer_fetch::GitHubReleaseFetcher,
    installer_host_fs as fs, installer_hosting,
    installer_release::{self as release, Inventory},
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
    installer_verify::{
        check_private_asset, read_private_bytes, read_private_record, VerificationTools,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Cursor, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "signed Cloudflare add-on is absent, changed or unsupported; preserve installation evidence";
pub(crate) const IMAGE_REPOSITORY: &str = "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper";
pub(crate) const RECORD: &str = "hosting-cloudflare-addon.json";
const DIRECTORY: &str = "hosting-cloudflare";
const MANIFEST: &str = "selfhost-cloudflare-images.json";
const ARCHIVE: &str = "selfhost-cloudflare-addon.zip";
const SBOM: &str = "cloudflared_wrapper.sbom.cdx.json";
const COMPOSE: &str = "compose.cloudflare.yml";
const SCRIPT: &str = "scripts/cloudflared-selfhost.sh";
const MAX_ARCHIVE: u64 = 1024 * 1024;
const MAX_PAYLOAD: u64 = 512 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    addon: String,
    platform: String,
    source_sha: String,
    release_tag: String,
    build_run_id: u64,
    build_run_attempt: u64,
    signer_workflow: String,
    services: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
    archive_sha256: String,
    archive_size_bytes: u64,
    sbom_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    installation: PathBuf,
    installation_id: uuid::Uuid,
    hosting_selection_sha256: String,
    inventory_sha256: String,
    assets: BTreeMap<String, Asset>,
}

struct Verified {
    receipt: Receipt,
    manifest: Manifest,
    receipt_sha256: String,
}

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty() && bytes.len() <= release::MAX_RECORD)?;
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn checksum(value: &str) -> Result<&str> {
    let bare = value.strip_prefix("sha256:").ok_or(REFUSED)?;
    require(digest(bare))?;
    Ok(bare)
}

pub(crate) fn is_connector_image(reference: &str) -> bool {
    reference
        .strip_prefix(IMAGE_REPOSITORY)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(digest)
}

fn manifest(bytes: &[u8], inventory: &Inventory) -> Result<Manifest> {
    let value: Manifest = decode(bytes)?;
    require(
        value.schema == "elevenid.hosting-addon/v1"
            && value.addon == "cloudflare-tunnel"
            && value.platform == "linux/amd64"
            && value.source_sha == inventory.source_sha
            && value.release_tag == inventory.release_tag
            && value.build_run_id == inventory.build_run_id
            && value.build_run_attempt == inventory.build_run_attempt
            && value.signer_workflow == release::build_workflow(&inventory.release_tag)?
            && value.services.len() == 1
            && value
                .services
                .get("cloudflared")
                .is_some_and(|image| is_connector_image(image))
            && value
                .files
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([COMPOSE, SCRIPT])
            && (1..=MAX_ARCHIVE).contains(&value.archive_size_bytes),
    )?;
    for hash in value
        .files
        .values()
        .chain([&value.archive_sha256, &value.sbom_sha256])
    {
        checksum(hash)?;
    }
    Ok(value)
}

fn payload(archive: &[u8], manifest: &Manifest) -> Result<BTreeMap<String, Vec<u8>>> {
    require(
        archive.len() as u64 == manifest.archive_size_bytes
            && archive.len() as u64 <= MAX_ARCHIVE
            && release::sha256(archive) == checksum(&manifest.archive_sha256)?
            && crate::installer_artifacts::central_directory_bound(archive)? == 2,
    )?;
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).map_err(|_| REFUSED)?;
    require(zip.len() == 2)?;
    let mut total = 0u64;
    let mut files = BTreeMap::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|_| REFUSED)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| REFUSED)?
            .to_owned();
        require(
            manifest.files.contains_key(&name)
                && !files.contains_key(&name)
                && !entry.is_dir()
                && !entry.encrypted()
                && entry.compression() == zip::CompressionMethod::Stored
                && entry.unix_mode() == Some(libc::S_IFREG | 0o644)
                && entry.extra_data().is_none()
                && entry.size() > 0,
        )?;
        total = total.checked_add(entry.size()).ok_or(REFUSED)?;
        require(total <= MAX_PAYLOAD)?;
        let size = entry.size();
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(size + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        require(
            bytes.len() as u64 == size
                && release::sha256(&bytes) == checksum(&manifest.files[&name])?,
        )?;
        files.insert(name, bytes);
    }
    // The producer emits JSON, which Compose also accepts as YAML. Reuse the
    // installer's strict decoder rather than interpreting arbitrary YAML tags.
    let model = crate::installer_json::decode(&files[COMPOSE]).map_err(|_| REFUSED)?;
    let root = model.as_object().ok_or(REFUSED)?;
    let services = root
        .get("services")
        .and_then(|v| v.as_object())
        .ok_or(REFUSED)?;
    require(
        root.len() == 1
            && services.len() == 1
            && services
                .get("cloudflared")
                .and_then(|v| v.get("image"))
                .and_then(|v| v.as_str())
                == Some(manifest.services["cloudflared"].as_str()),
    )?;
    Ok(files)
}

fn create_directory(parent: &File, name: &str) -> Result<File> {
    let entry = CString::new(name).map_err(|_| REFUSED)?;
    require(!name.contains('/') && !name.contains('\\') && name != "." && name != "..")?;
    require(unsafe { libc::mkdirat(parent.as_raw_fd(), entry.as_ptr(), 0o700) } == 0)?;
    let child = fs::open_child(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    require(unsafe { libc::fchmod(child.as_raw_fd(), 0o700) } == 0)?;
    child
        .sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED)?;
    Ok(child)
}

fn write_runtime(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let entry = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    parent.sync_all().map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    file.sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED.into())
}

fn extract(directory: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let parent = fs::directory(directory, REFUSED)?;
    let runtime = create_directory(&parent, "runtime")?;
    let scripts = create_directory(&runtime, "scripts")?;
    write_runtime(&runtime, COMPOSE, &files[COMPOSE])?;
    write_runtime(&scripts, "cloudflared-selfhost.sh", &files[SCRIPT])?;
    fs::require_directory_binding(directory, &parent, REFUSED)
}

fn runtime_files(directory: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let runtime = fs::directory(&directory.join("runtime"), REFUSED)?;
    let scripts = fs::directory(&directory.join("runtime/scripts"), REFUSED)?;
    require(
        fs::file_names(&runtime, REFUSED)? == BTreeSet::from([COMPOSE.into(), "scripts".into()])
            && fs::file_names(&scripts, REFUSED)?
                == BTreeSet::from(["cloudflared-selfhost.sh".into()]),
    )?;
    for (parent, name, key) in [
        (&runtime, COMPOSE, COMPOSE),
        (&scripts, "cloudflared-selfhost.sh", SCRIPT),
    ] {
        let file = fs::open_child(parent, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
        let meta = file.metadata().map_err(|_| REFUSED)?;
        require(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 == 0o444
                && meta.len() == files[key].len() as u64,
        )?;
        let mut bytes = Vec::new();
        file.take(MAX_PAYLOAD + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        require(bytes == files[key])?;
    }
    fs::require_directory_binding(&directory.join("runtime"), &runtime, REFUSED)?;
    fs::require_directory_binding(&directory.join("runtime/scripts"), &scripts, REFUSED)
}

fn asset_limit(name: &str) -> Option<u64> {
    match name {
        MANIFEST => Some(65536),
        ARCHIVE => Some(MAX_ARCHIVE),
        SBOM => Some(16 * 1024 * 1024),
        _ => [MANIFEST, ARCHIVE, SBOM]
            .iter()
            .any(|base| {
                name == format!("{base}.sigstore.json")
                    || name == format!("{base}.provenance.jsonl")
            })
            .then_some(1024 * 1024),
    }
}

fn inventory(bytes: &[u8], journal: &Journal) -> Result<Inventory> {
    require(format!("sha256:{}", release::sha256(bytes)) == journal.identity().inventory_sha256)?;
    let value = release::parse_inventory(bytes)?;
    require(
        value.source_sha == journal.identity().source_sha
            && value.release_tag == journal.identity().release_tag,
    )?;
    Ok(value)
}

fn verified(raw: &[u8], inventory_bytes: &[u8], journal: &Journal) -> Result<Verified> {
    let receipt_sha256 = release::sha256(raw);
    require(journal.hosting_addon_sha256() == Some(receipt_sha256.as_str()))?;
    let receipt: Receipt = decode(raw)?;
    require(
        receipt.schema == "elevenid.installer-hosting-addon/v1"
            && receipt.installation_id == journal.installation_id()
            && Some(receipt.hosting_selection_sha256.as_str())
                == journal.hosting_selection_sha256()
            && receipt.inventory_sha256 == journal.identity().inventory_sha256
            && receipt.assets.len() == 9,
    )?;
    let inventory = inventory(inventory_bytes, journal)?;
    fs::directory(&receipt.installation, REFUSED)?;
    let directory = receipt.installation.join("downloads").join(DIRECTORY);
    let held = fs::directory(&directory, REFUSED)?;
    for (name, asset) in &receipt.assets {
        let limit = asset_limit(name).ok_or(REFUSED)?;
        require(digest(&asset.sha256) && (1..=limit).contains(&asset.size))?;
        check_private_asset(&directory.join(name), &asset.sha256, asset.size)?;
    }
    let expected = [MANIFEST, ARCHIVE, SBOM]
        .into_iter()
        .flat_map(|name| {
            [
                name.to_owned(),
                format!("{name}.sigstore.json"),
                format!("{name}.provenance.jsonl"),
            ]
        })
        .collect::<BTreeSet<_>>();
    require(receipt.assets.keys().cloned().collect::<BTreeSet<_>>() == expected)?;
    let manifest_bytes = read_private_record(&directory.join(MANIFEST))?;
    require(release::sha256(&manifest_bytes) == receipt.assets[MANIFEST].sha256)?;
    let manifest = manifest(&manifest_bytes, &inventory)?;
    require(
        receipt.assets[ARCHIVE].sha256 == checksum(&manifest.archive_sha256)?
            && receipt.assets[ARCHIVE].size == manifest.archive_size_bytes
            && receipt.assets[SBOM].sha256 == checksum(&manifest.sbom_sha256)?,
    )?;
    let archive = read_private_bytes(&directory.join(ARCHIVE), MAX_ARCHIVE)?;
    let files = payload(&archive, &manifest)?;
    runtime_files(&directory, &files)?;
    fs::require_directory_binding(&directory, &held, REFUSED)?;
    Ok(Verified {
        receipt,
        manifest,
        receipt_sha256,
    })
}

fn load(state: &LockedInspection) -> Result<Option<Verified>> {
    let selected =
        installer_hosting::load(state)?.is_some_and(|selection| selection.connector().is_some());
    let raw = state.diagnostic_record(RECORD, true)?;
    if !selected {
        require(raw.is_none() && state.journal().hosting_addon_sha256().is_none())?;
        return Ok(None);
    }
    let verified = verified(
        &raw.ok_or(REFUSED)?,
        &state.read_evidence("installer-inventory.json")?,
        state.journal(),
    )?;
    state.require_path_binding(&verified.receipt.installation)?;
    Ok(Some(verified))
}

async fn sidecars(
    fetcher: &GitHubReleaseFetcher,
    tag: &str,
    name: &str,
    directory: &Path,
) -> Result<()> {
    for suffix in [".sigstore.json", ".provenance.jsonl"] {
        let asset = format!("{name}{suffix}");
        fetcher
            .fetch_sidecar(tag, &asset, &directory.join(&asset))
            .await?;
    }
    Ok(())
}

/// No fetch occurs for local/direct/proxy installations without a connector.
/// A selected but unpublished add-on fails here, before any Docker mutation.
pub(crate) async fn prepare(
    installation: &Path,
    state: &mut InstallerState,
    expected: &Inventory,
    tools: &VerificationTools,
) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    let selected = state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        require(
            view.journal().hosting_addon_sha256().is_none()
                && view.diagnostic_record(RECORD, true)?.is_none(),
        )?;
        let current = inventory(
            &view.read_evidence("installer-inventory.json")?,
            view.journal(),
        )?;
        require(&current == expected)?;
        Ok(installer_hosting::load(view)?.is_some_and(|selection| selection.connector().is_some()))
    })?;
    if !selected {
        return Ok(());
    }
    let parent_path = installation.join("downloads");
    let parent = fs::directory(&parent_path, REFUSED)?;
    let held = create_directory(&parent, DIRECTORY)?;
    let directory = parent_path.join(DIRECTORY);
    let fetcher = GitHubReleaseFetcher::new()?;
    fetcher.fetch_record(&expected.release_tag, MANIFEST, &directory.join(MANIFEST)).await
        .map_err(|_| "selected Cloudflare add-on is unavailable; publish the signed optional add-on for this exact release before retrying")?;
    sidecars(&fetcher, &expected.release_tag, MANIFEST, &directory).await?;
    let workflow = release::build_workflow(&expected.release_tag)?;
    let verify = |name: &str| {
        tools.verify(
            &directory.join(name),
            workflow,
            &expected.source_sha,
            expected.build_run_id,
            expected.build_run_attempt,
        )
    };
    let manifest_digest = verify(MANIFEST)?;
    let manifest_bytes = read_private_record(&directory.join(MANIFEST))?;
    require(manifest_digest == release::sha256(&manifest_bytes))?;
    let manifest = manifest(&manifest_bytes, expected)?;
    fetcher
        .fetch_verified(
            &expected.release_tag,
            ARCHIVE,
            &directory.join(ARCHIVE),
            manifest.archive_size_bytes,
            checksum(&manifest.archive_sha256)?,
        )
        .await?;
    sidecars(&fetcher, &expected.release_tag, ARCHIVE, &directory).await?;
    require(verify(ARCHIVE)? == checksum(&manifest.archive_sha256)?)?;
    let sbom = fetcher
        .fetch_hosting_sbom(&expected.release_tag, &directory.join(SBOM))
        .await?;
    sidecars(&fetcher, &expected.release_tag, SBOM, &directory).await?;
    require(
        verify(SBOM)? == checksum(&manifest.sbom_sha256)?
            && sbom.sha256 == checksum(&manifest.sbom_sha256)?,
    )?;
    let mut assets = BTreeMap::from([
        (
            MANIFEST.into(),
            Asset {
                sha256: manifest_digest,
                size: manifest_bytes.len() as u64,
            },
        ),
        (
            ARCHIVE.into(),
            Asset {
                sha256: checksum(&manifest.archive_sha256)?.into(),
                size: manifest.archive_size_bytes,
            },
        ),
        (
            SBOM.into(),
            Asset {
                sha256: sbom.sha256,
                size: sbom.bytes,
            },
        ),
    ]);
    for name in [MANIFEST, ARCHIVE, SBOM] {
        for suffix in [".sigstore.json", ".provenance.jsonl"] {
            let name = format!("{name}{suffix}");
            let bytes = read_private_bytes(&directory.join(&name), 1024 * 1024)?;
            assets.insert(
                name,
                Asset {
                    sha256: release::sha256(&bytes),
                    size: bytes.len() as u64,
                },
            );
        }
    }
    let files = payload(
        &read_private_bytes(&directory.join(ARCHIVE), MAX_ARCHIVE)?,
        &manifest,
    )?;
    extract(&directory, &files)?;
    runtime_files(&directory, &files)?;
    fs::require_directory_binding(&parent_path, &parent, REFUSED)?;
    fs::require_directory_binding(&directory, &held, REFUSED)?;
    state.with_inspection(|view| view.require_path_binding(installation))?;
    let receipt = Receipt {
        schema: "elevenid.installer-hosting-addon/v1".into(),
        installation: installation.into(),
        installation_id: state.journal().installation_id(),
        hosting_selection_sha256: state
            .journal()
            .hosting_selection_sha256()
            .ok_or(REFUSED)?
            .into(),
        inventory_sha256: state.journal().identity().inventory_sha256.clone(),
        assets,
    };
    let raw = serde_json::to_vec(&receipt).map_err(|_| REFUSED)?;
    state.write_evidence(RECORD, &raw)?;
    state.bind_hosting_addon(&release::sha256(&raw))?;
    state.with_inspection(|view| require(load(view)?.is_some()))
}

pub(crate) fn environment(state: &LockedInspection) -> Result<BTreeMap<String, String>> {
    let Some(verified) = load(state)? else {
        return Ok(BTreeMap::new());
    };
    let path = verified
        .receipt
        .installation
        .join("downloads")
        .join(DIRECTORY)
        .join("runtime");
    let value = path.to_str().ok_or(REFUSED)?;
    require(!value.chars().any(char::is_control))?;
    Ok(BTreeMap::from([(
        "MARTY_CLOUDFLARE_ADDON_DIR".into(),
        value.into(),
    )]))
}

pub(crate) fn approved_images(state: &LockedInspection) -> Result<BTreeSet<String>> {
    Ok(load(state)?.map_or_else(BTreeSet::new, |verified| {
        verified.manifest.services.into_values().collect()
    }))
}

fn add_bound(files: &mut Vec<BoundFile>, file: BoundFile) -> Result<()> {
    let existing = files
        .iter()
        .filter(|value| value.path == file.path)
        .collect::<Vec<_>>();
    if existing.is_empty() {
        files.push(file);
    } else {
        require(existing.len() == 1 && existing[0].sha256 == file.sha256)?;
    }
    Ok(())
}

/// The caller already owns the installation lock; do not acquire another one.
/// Maintenance resets Compose layers but retains evidence, so this is idempotent.
pub(crate) fn bind_inputs(inputs: &mut ComposeInputs) -> Result<()> {
    let selected = installer_hosting::for_inputs(inputs)?
        .is_some_and(|selection| selection.connector().is_some());
    let journal = InstallerState::inspect(&inputs.installation)?;
    let record = inputs.installation.join("evidence").join(RECORD);
    if !selected {
        require(
            journal.hosting_addon_sha256().is_none()
                && !inputs
                    .approved_images
                    .iter()
                    .any(|image| is_connector_image(image))
                && !inputs.bound_inputs.iter().any(|file| file.path == record),
        )?;
        return match std::fs::symlink_metadata(record) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(REFUSED.into()),
        };
    }
    let verified = verified(
        &read_private_record(&record)?,
        &read_private_record(
            &inputs
                .installation
                .join("evidence/installer-inventory.json"),
        )?,
        &journal,
    )?;
    require(
        verified.receipt.installation == inputs.installation
            && inputs.project == journal.compose_project(),
    )?;
    let directory = inputs.installation.join("downloads").join(DIRECTORY);
    let runtime = directory.join("runtime");
    add_bound(
        &mut inputs.bound_inputs,
        BoundFile {
            path: record,
            sha256: verified.receipt_sha256,
        },
    )?;
    for (name, asset) in &verified.receipt.assets {
        // The large SBOM is authenticated by the journal-bound receipt and
        // checked above, but is not an input to Compose's 2 MiB file boundary.
        if name != SBOM {
            add_bound(
                &mut inputs.bound_inputs,
                BoundFile {
                    path: directory.join(name),
                    sha256: asset.sha256.clone(),
                },
            )?;
        }
    }
    add_bound(
        &mut inputs.bound_inputs,
        BoundFile {
            path: runtime.join(SCRIPT),
            sha256: checksum(&verified.manifest.files[SCRIPT])?.into(),
        },
    )?;
    let overlay = BoundFile {
        path: runtime.join(COMPOSE),
        sha256: checksum(&verified.manifest.files[COMPOSE])?.into(),
    };
    add_bound(&mut inputs.files, overlay.clone())?;
    require(
        inputs
            .files
            .last()
            .is_some_and(|file| file.path == overlay.path && file.sha256 == overlay.sha256),
    )?;
    inputs.readonly_bind_roots.insert(runtime);
    inputs
        .approved_images
        .insert(verified.manifest.services["cloudflared"].clone());
    if !inputs.services.is_empty()
        && !inputs
            .services
            .iter()
            .any(|service| service == "cloudflared")
    {
        inputs.services.push("cloudflared".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "installer_hosting_addon_tests.rs"]
mod tests;
