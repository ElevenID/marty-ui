//! Self-host distribution packaging. Does not deploy, authenticate releases, or read operator secrets.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

pub mod process;
mod publication;
pub mod transform;
pub type Result<T> = std::result::Result<T, String>;
pub const MARKER: &str = ".marty-selfhost-bundle.json";
const SCHEMA: &str = "marty.selfhost-bundle-files/v1";
const MANIFEST: &str = "deploy-config/bundles/selfhost.json";
const DEFAULT_ASSETS: &[&str] = &[
    "docker-compose.selfhost.prod.yml",
    "docker-compose.selfhost.bundle.override.yml",
    ".env.selfhost.production.example",
    "SELFHOST_BUNDLE.md",
    "docker/init-databases.sh",
    "docker/nginx-selfhost.prod.conf.template",
    "docker/tunnel-nginx-proxy.edge.conf",
    "docker/openbao-init.sh",
    "docker/secrets/selfhost.example",
    "config/keycloak",
    "scripts/bootstrap-selfhost-vault.sh",
    "scripts/cloudflared-selfhost.sh",
    "scripts/keycloak-selfhost-start.sh",
    "scripts/load-openbao-token-and-start.sh",
    "scripts/load-secrets-env.sh",
    "scripts/nginx-entrypoint-selfhost.sh",
    "scripts/setup-keycloak-selfhost-production.sh",
    "scripts/setup-keycloak.sh",
];

#[derive(Clone, Deserialize)]
pub struct Render {
    pub env_file: String,
    pub compose_files: Vec<String>,
    pub output_file: String,
    pub strip_build_blocks: bool,
    pub relativize_paths: bool,
    pub no_interpolate: bool,
}
impl Default for Render {
    fn default() -> Self {
        Self {
            env_file: ".env.selfhost.production.example".into(),
            compose_files: vec![
                "docker-compose.selfhost.prod.yml".into(),
                "docker-compose.selfhost.bundle.override.yml".into(),
            ],
            output_file: "docker-compose.yml".into(),
            strip_build_blocks: true,
            relativize_paths: true,
            no_interpolate: true,
        }
    }
}
#[derive(Deserialize)]
struct Manifest {
    assets: Vec<String>,
    #[serde(default)]
    render: Render,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    schema: String,
    files: BTreeMap<String, String>,
    directories: Vec<String>,
}

pub struct Options {
    pub repo: PathBuf,
    pub output: PathBuf,
    /// Exact final ZIP path; the CLI preserves the legacy appended .zip suffix.
    pub archive: Option<PathBuf>,
    pub replace: bool,
}
#[derive(Debug)]
pub struct Published {
    pub output: PathBuf,
    pub archive: Option<PathBuf>,
    /// An explicitly replaced bundle is retained here, never recursively deleted.
    pub backup: Option<PathBuf>,
}

fn failure(message: &str) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |_| message.to_owned()
}
fn plain(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    !metadata.file_type().is_symlink()
}
pub fn relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || value.contains(':')
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err("Bundle paths must be nonempty contained relative paths".into());
    }
    let normalized: PathBuf = path
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect();
    if normalized.as_os_str().is_empty() {
        return Err("Bundle paths must identify a contained asset, not the root".into());
    }
    Ok(normalized)
}
fn check_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if !plain(&metadata) => {
                return Err("Symlink/reparse paths are not allowed".into())
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Cannot inspect packaging path".into()),
        }
    }
    Ok(())
}
fn destination(path: &Path, repo: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("Output paths must not contain parent traversal".into());
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(failure("Cannot inspect working directory"))?
            .join(path)
    };
    // Preserve harmless ./ syntax without allowing parent traversal or treating
    // an existing directory's trailing dot as a new child output.
    let path: PathBuf = path
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect();
    check_ancestors(&path)?;
    let mut ancestor = path.parent().ok_or("Output needs a containing directory")?;
    let mut missing = Vec::new();
    while !ancestor.exists() {
        missing.push(
            ancestor
                .file_name()
                .ok_or("Output parent is unavailable")?
                .to_owned(),
        );
        ancestor = ancestor.parent().ok_or("Output parent is unavailable")?;
    }
    let mut parent = ancestor
        .canonicalize()
        .map_err(failure("Output parent is unavailable"))?;
    for component in missing.into_iter().rev() {
        parent.push(component);
    }
    let result = parent.join(path.file_name().ok_or("Output needs a filename")?);
    if repo.starts_with(&result)
        || result.join(".git").exists()
        || result.join("rust/Cargo.toml").exists()
    {
        return Err("Repository/workspace roots cannot be packaging outputs".into());
    }
    Ok(result)
}
fn entries(root: &Path) -> Result<Vec<(PathBuf, bool)>> {
    fn visit(root: &Path, path: &Path, result: &mut Vec<(PathBuf, bool)>) -> Result<()> {
        let meta = fs::symlink_metadata(path).map_err(failure("Cannot inspect bundle asset"))?;
        if !plain(&meta) {
            return Err("Symlink/reparse bundle assets are forbidden".into());
        }
        if meta.is_dir() {
            result.push((
                path.strip_prefix(root)
                    .map_err(|_| "Asset escapes bundle root")?
                    .to_owned(),
                true,
            ));
            for entry in fs::read_dir(path).map_err(failure("Cannot enumerate bundle assets"))? {
                visit(
                    root,
                    &entry
                        .map_err(failure("Cannot inspect bundle directory entry"))?
                        .path(),
                    result,
                )?;
            }
        } else if meta.is_file() {
            result.push((
                path.strip_prefix(root)
                    .map_err(|_| "Asset escapes bundle root")?
                    .to_owned(),
                false,
            ));
        } else {
            return Err("Bundle assets must be ordinary files or directories".into());
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(root, root, &mut paths)?;
    paths.sort();
    Ok(paths)
}
fn inventory(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(entries(root)?
        .into_iter()
        .filter_map(|(path, directory)| (!directory).then_some(path))
        .collect())
}
fn directories(root: &Path) -> Result<Vec<String>> {
    Ok(entries(root)?
        .into_iter()
        .filter_map(|(path, directory)| {
            directory.then(|| path.to_string_lossy().replace('\\', "/"))
        })
        .collect())
}
fn copy_asset(source: &Path, destination: &Path, top_level: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(source).map_err(failure("Bundle asset is missing"))?;
    if !plain(&metadata) {
        return Err("Symlink/reparse bundle assets are forbidden".into());
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination).map_err(failure("Cannot create staged asset directory"))?;
        for entry in fs::read_dir(source).map_err(failure("Cannot enumerate source asset"))? {
            let entry = entry.map_err(failure("Cannot inspect source asset"))?;
            copy_asset(&entry.path(), &destination.join(entry.file_name()), false)?;
        }
        fs::set_permissions(destination, metadata.permissions())
            .map_err(failure("Cannot preserve directory permissions"))?;
    } else if metadata.is_file() {
        fs::create_dir_all(destination.parent().unwrap())
            .map_err(failure("Cannot create staged parent"))?;
        fs::copy(source, destination).map_err(failure("Cannot copy staged asset"))?;
        let final_permissions = metadata.permissions();
        #[cfg(unix)]
        let final_permissions = {
            use std::os::unix::fs::PermissionsExt;
            if top_level && destination.extension().is_some_and(|ext| ext == "sh") {
                fs::Permissions::from_mode(final_permissions.mode() | 0o755)
            } else {
                final_permissions
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                destination,
                fs::Permissions::from_mode(final_permissions.mode() | 0o200),
            )
            .map_err(failure("Cannot prepare owned copy metadata"))?;
        }
        #[cfg(windows)]
        #[allow(clippy::permissions_set_readonly_false)]
        // Windows-only copy attribute; Unix uses owner-write mode above.
        {
            let _ = top_level;
            let mut writable = final_permissions.clone();
            writable.set_readonly(false);
            fs::set_permissions(destination, writable)
                .map_err(failure("Cannot prepare owned copy metadata"))?;
        }
        fs::File::options()
            .write(true)
            .open(destination)
            .map_err(failure("Cannot preserve asset timestamps"))?
            .set_times(
                fs::FileTimes::new().set_modified(
                    metadata
                        .modified()
                        .map_err(failure("Cannot inspect asset timestamp"))?,
                ),
            )
            .map_err(failure("Cannot preserve asset timestamp"))?;
        fs::set_permissions(destination, final_permissions)
            .map_err(failure("Cannot preserve asset permissions"))?;
    } else {
        return Err("Bundle assets must be ordinary files or directories".into());
    }
    Ok(())
}
fn read_manifest(repo: &Path) -> Result<Manifest> {
    let path = repo.join(MANIFEST);
    if !path.exists() {
        return Ok(Manifest {
            assets: DEFAULT_ASSETS.iter().map(|s| (*s).into()).collect(),
            render: Render::default(),
        });
    }
    check_ancestors(&path)?;
    serde_json::from_slice(&fs::read(path).map_err(failure("Cannot read bundle manifest"))?)
        .map_err(|_| {
            "Bundle manifest must define an assets list of strings and a valid render contract"
                .into()
        })
}
pub fn default_output(repo: &Path) -> Result<PathBuf> {
    check_ancestors(repo)?;
    let repo = repo
        .canonicalize()
        .map_err(failure("Repository root is unavailable"))?;
    let dist = repo.join("dist");
    check_ancestors(&dist)?;
    if !dist.exists() {
        fs::create_dir(&dist).map_err(failure("Cannot create default dist directory"))?;
    }
    Ok(dist.join("selfhost-bundle"))
}
pub fn render_arguments(render: &Render) -> Vec<String> {
    let mut args = vec!["--env-file".into(), render.env_file.clone()];
    for file in &render.compose_files {
        args.extend(["-f".into(), file.clone()]);
    }
    args.extend(["config".into(), "--no-interpolate".into()]);
    args
}
fn source_closure(stage: &Path, files: &[String]) -> Result<BTreeSet<PathBuf>> {
    let mut pending: Vec<_> = files.iter().map(|s| relative(s)).collect::<Result<_>>()?;
    let mut closure = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !closure.insert(path.clone()) {
            continue;
        }
        let raw = fs::read_to_string(stage.join(&path))
            .map_err(failure("Staged Compose source is missing"))?;
        let document: serde_yaml::Value =
            serde_yaml::from_str(&raw).map_err(|_| "Invalid source Compose YAML")?;
        if let Some(services) = document
            .get("services")
            .and_then(serde_yaml::Value::as_mapping)
        {
            for service in services.values() {
                if let Some(file) = service
                    .get("extends")
                    .and_then(|value| value.get("file"))
                    .and_then(serde_yaml::Value::as_str)
                {
                    pending.push(path.parent().unwrap_or(Path::new("")).join(relative(file)?));
                }
            }
        }
    }
    Ok(closure)
}
pub fn relativize(text: &str, stage: &Path) -> Result<String> {
    fn normalized(value: &str) -> String {
        let value = value.replace('\\', "/");
        if let Some(unc) = value.strip_prefix("//?/UNC/") {
            format!("//{unc}")
        } else {
            value.strip_prefix("//?/").unwrap_or(&value).to_owned()
        }
    }
    let root = normalized(&stage.to_string_lossy());
    let field = regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_-]*:").unwrap();
    let interpolation =
        regex::Regex::new(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::[-?+]|[-?+])[^{}\r\n]*)?\}").unwrap();
    let mut output = Vec::new();
    let lines: Vec<_> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let stripped = line.trim();
        let mut rewritten = line.to_owned();
        let mut consumed = 1;
        for key in ["source: ", "file: ", "- source: "] {
            if let Some(value) = stripped.strip_prefix(key) {
                // Compose quotes path values when needed; preserve scalar meaning.
                let indent = line.len() - line.trim_start().len();
                while index + consumed < lines.len() {
                    let next = lines[index + consumed];
                    if next.trim().is_empty() || next.len() - next.trim_start().len() <= indent {
                        break;
                    }
                    if key.starts_with("- ")
                        && next.len() - next.trim_start().len() == indent + 2
                        && field.is_match(next.trim_start())
                    {
                        break;
                    }
                    consumed += 1;
                }
                let fragment = lines[index..index + consumed].join("\n");
                let scalar = serde_yaml::from_str::<serde_yaml::Value>(&fragment)
                    .ok()
                    .and_then(|document| {
                        let document = document
                            .as_sequence()
                            .and_then(|sequence| sequence.first())
                            .unwrap_or(&document);
                        document
                            .get(
                                key.trim_start_matches("- ")
                                    .trim_end_matches(' ')
                                    .trim_end_matches(':'),
                            )
                            .and_then(serde_yaml::Value::as_str)
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| value.to_owned());
                let scalar = normalized(&scalar);
                if scalar.starts_with(&root) {
                    let suffix = scalar
                        .strip_prefix(&format!("{root}/"))
                        .ok_or("Rendered path escapes staged bundle")?;
                    // Unexpanded operator-directory selectors are not literal source
                    // asset names. Validate their surrounding path without rejecting
                    // Compose's required/default expression punctuation.
                    let checked = interpolation.replace_all(suffix, "operator-setting");
                    if checked.contains("${") {
                        return Err("Unsupported nested rendered path interpolation".into());
                    }
                    relative(&checked)?;
                    let value = format!("./{suffix}");
                    // A leading operator directory may resolve to an absolute
                    // path. Prefixing it with ./ would anchor that path under
                    // the bundle. File and both recognized bind-source forms
                    // must preserve the same interpolation semantics.
                    let value = value
                        .strip_prefix("./${")
                        .map(|rest| format!("${{{rest}"))
                        .unwrap_or(value);
                    let value = if value.contains([' ', '#', ':']) {
                        serde_json::to_string(&value).unwrap()
                    } else {
                        value
                    };
                    rewritten = format!(
                        "{}{}{}",
                        &line[..line.len() - line.trim_start().len()],
                        key,
                        value
                    );
                }
            }
        }
        output.push(rewritten);
        if output.last().is_some_and(|rewritten| rewritten == line) {
            output.extend(
                lines[index + 1..index + consumed]
                    .iter()
                    .map(|line| (*line).to_owned()),
            );
        }
        index += consumed;
    }
    Ok(format!("{}\n", output.join("\n").trim_end()))
}
fn hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for path in inventory(root)? {
        if path == Path::new(MARKER) {
            continue;
        }
        let bytes = fs::read(root.join(&path)).map_err(failure("Cannot read bundle file"))?;
        hashes.insert(
            path.to_string_lossy().replace('\\', "/"),
            format!("{:x}", Sha256::digest(bytes)),
        );
    }
    Ok(hashes)
}
fn verify_owned(output: &Path) -> Result<()> {
    check_ancestors(output)?;
    let bytes = fs::read(output.join(MARKER))
        .map_err(failure("Existing output is not a recognized owned bundle"))?;
    let marker: Ownership =
        serde_json::from_slice(&bytes).map_err(|_| "Existing bundle ownership is invalid")?;
    if marker.schema != SCHEMA
        || marker.files != hashes(output)?
        || marker.directories != directories(output)?
    {
        return Err(
            "Existing bundle was modified or is not an owned bundle; it is preserved".into(),
        );
    }
    Ok(())
}
fn write_archive(root: &Path, name: &str, file: fs::File) -> Result<fs::File> {
    let mut writer = zip::ZipWriter::new(file);
    for (path, directory) in entries(root)? {
        let name = format!("{name}/{}", path.to_string_lossy().replace('\\', "/"));
        let mut options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            options = options.unix_permissions(
                fs::metadata(root.join(&path))
                    .map_err(failure("Cannot inspect archive file mode"))?
                    .permissions()
                    .mode(),
            );
        }
        #[cfg(not(unix))]
        {
            options = options.unix_permissions(if directory { 0o755 } else { 0o644 });
        }
        if directory {
            writer
                .add_directory(name, options)
                .map_err(|_| "Cannot start ZIP directory")?;
            continue;
        }
        writer
            .start_file(name, options)
            .map_err(|_| "Cannot start ZIP member")?;
        let mut source =
            fs::File::open(root.join(path)).map_err(failure("Cannot read ZIP source"))?;
        std::io::copy(&mut source, &mut writer).map_err(failure("Cannot write ZIP member"))?;
    }
    writer
        .finish()
        .map_err(|_| "Cannot finalize ZIP archive".into())
}

pub fn package(
    options: &Options,
    renderer: impl FnOnce(&Path, &[String]) -> Result<String>,
) -> Result<Published> {
    package_with_publication(options, renderer, publication::rename_noreplace)
}
fn package_with_publication(
    options: &Options,
    renderer: impl FnOnce(&Path, &[String]) -> Result<String>,
    publish: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<Published> {
    check_ancestors(&options.repo)?;
    let repo = options
        .repo
        .canonicalize()
        .map_err(failure("Repository root is unavailable"))?;
    let output = destination(&options.output, &repo)?;
    let archive = options
        .archive
        .as_ref()
        .map(|path| destination(path, &repo))
        .transpose()?;
    if let Some(archive) = &archive {
        if archive.starts_with(&output) || output.starts_with(archive) || archive.exists() {
            return Err("Archive must be a new path outside the output directory".into());
        }
    }
    if output.exists() {
        if !options.replace {
            return Err(
                "Output already exists; use --replace only for a verified owned bundle".into(),
            );
        }
        verify_owned(&output)?;
    }
    let manifest = read_manifest(&repo)?;
    if !manifest.render.no_interpolate
        || !manifest.render.strip_build_blocks
        || !manifest.render.relativize_paths
    {
        return Err(
            "Bundle render must retain no-interpolate, build stripping and relative paths".into(),
        );
    }
    let final_compose = relative(&manifest.render.output_file)?;
    relative(&manifest.render.env_file)?;
    let assets: Vec<_> = manifest
        .assets
        .iter()
        .map(|s| relative(s))
        .collect::<Result<_>>()?;
    for asset in &assets {
        check_ancestors(&repo.join(asset))?;
        if output.starts_with(repo.join(asset))
            || archive
                .as_ref()
                .is_some_and(|p| p.starts_with(repo.join(asset)))
        {
            return Err("Packaging outputs must not overlap source assets".into());
        }
    }
    // Preserve the original nested-output convenience, but only after validating
    // all source/output boundaries and existing ancestors. No parent is deleted.
    fs::create_dir_all(output.parent().unwrap()).map_err(failure("Cannot create output parent"))?;
    if let Some(archive) = &archive {
        fs::create_dir_all(archive.parent().unwrap())
            .map_err(failure("Cannot create archive parent"))?;
    }
    let stage = tempfile::Builder::new()
        .prefix(".selfhost-stage-")
        .tempdir_in(output.parent().unwrap())
        .map_err(failure("Cannot create owned staging directory"))?;
    for asset in assets {
        copy_asset(&repo.join(&asset), &stage.path().join(&asset), true)?;
    }
    fs::rename(
        stage.path().join("SELFHOST_BUNDLE.md"),
        stage.path().join("README.md"),
    )
    .map_err(failure("Self-host README source is missing"))?;
    let sources = source_closure(stage.path(), &manifest.render.compose_files)?;
    if sources.contains(&final_compose) {
        return Err("Rendered output overlaps source Compose input".into());
    }
    let rendered = renderer(stage.path(), &render_arguments(&manifest.render))?;
    let rendered = relativize(&transform::strip_build_blocks(&rendered), stage.path())?;
    transform::validate_strict(&rendered)?;
    fs::write(stage.path().join(final_compose), rendered)
        .map_err(failure("Cannot write rendered Compose"))?;
    for source in sources {
        fs::remove_file(stage.path().join(source))
            .map_err(failure("Cannot remove owned staged Compose source"))?;
    }
    for path in inventory(stage.path())? {
        let bytes =
            fs::read(stage.path().join(path)).map_err(failure("Cannot validate staged file"))?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            transform::validate_customer_text(text)?;
        }
    }
    let marker = Ownership {
        schema: SCHEMA.into(),
        files: hashes(stage.path())?,
        directories: directories(stage.path())?,
    };
    fs::write(
        stage.path().join(MARKER),
        serde_json::to_vec_pretty(&marker).unwrap(),
    )
    .map_err(failure("Cannot write bundle ownership"))?;
    let staged_archive = archive
        .as_ref()
        .map(|path| -> Result<_> {
            let file = tempfile::NamedTempFile::new_in(path.parent().unwrap())
                .map_err(failure("Cannot stage ZIP"))?;
            let (handle, temporary) = file.into_parts();
            let mut handle = write_archive(
                stage.path(),
                output
                    .file_name()
                    .unwrap()
                    .to_str()
                    .ok_or("Output name must be UTF-8")?,
                handle,
            )?;
            handle.flush().map_err(failure("Cannot flush ZIP"))?;
            handle.sync_all().map_err(failure("Cannot sync ZIP"))?;
            drop(handle);
            Ok(temporary)
        })
        .transpose()?;
    // Revalidate immediately before publication. Reject races rather than removing foreign paths.
    let backup = if output.exists() {
        if !options.replace {
            return Err("Output appeared during packaging; it is preserved".into());
        }
        verify_owned(&output)?;
        let backup_root = tempfile::Builder::new()
            .prefix(".selfhost-backup-")
            .tempdir_in(output.parent().unwrap())
            .map_err(failure("Cannot create owned backup directory"))?;
        let backup = backup_root.path().join("bundle");
        publication::rename_noreplace(&output, &backup)
            .map_err(failure("Cannot retain previous bundle"))?;
        let _ = backup_root.keep();
        Some(backup)
    } else {
        None
    };
    let staging_path = stage.keep();
    if let Err(error) = publish(&staging_path, &output) {
        return Err(format!(
            "Cannot publish bundle; staging retained ({}), previous bundle retained at ({}): {}",
            staging_path.display(),
            backup
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "no previous bundle".into()),
            error.kind()
        ));
    }
    if let (Some(temporary), Some(archive)) = (staged_archive, &archive) {
        if temporary.persist_noclobber(archive).is_err() {
            return Err("ZIP publication failed; completed bundle and any previous-bundle backup remain intact".into());
        }
    }
    Ok(Published {
        output,
        archive,
        backup,
    })
}

#[cfg(test)]
mod publication_pipeline_tests {
    use super::*;
    #[test]
    fn late_foreign_destination_preserves_verified_old_backup_and_new_staging() {
        for directory in [false, true] {
            let owned = tempfile::tempdir().unwrap();
            let repo = owned.path().join("repo");
            fs::create_dir_all(repo.join("deploy-config/bundles")).unwrap();
            fs::write(repo.join("SELFHOST_BUNDLE.md"), "original").unwrap();
            fs::write(repo.join("source.yml"), "services: {}\n").unwrap();
            fs::write(
                repo.join(MANIFEST),
                serde_json::json!({
                    "assets":["SELFHOST_BUNDLE.md", "source.yml"],
                    "render":{"env_file":"example.env", "compose_files":["source.yml"],
                        "output_file":"docker-compose.yml", "strip_build_blocks":true,
                        "relativize_paths":true,"no_interpolate":true}
                })
                .to_string(),
            )
            .unwrap();
            let mut options = Options {
                repo,
                output: owned.path().join("bundle"),
                archive: None,
                replace: false,
            };
            let renderer = |_: &Path, _: &[String]| {
                Ok("services:\n  app:\n    image: example:v1\n".to_owned())
            };
            package(&options, renderer).unwrap();
            options.replace = true;
            fs::write(options.repo.join("SELFHOST_BUNDLE.md"), "replacement").unwrap();
            let error = package_with_publication(&options, renderer, |stage, destination| {
                if directory {
                    fs::create_dir(destination).unwrap();
                } else {
                    fs::write(destination, "foreign").unwrap();
                }
                publication::rename_noreplace(stage, destination)
            })
            .unwrap_err();
            assert!(error.contains("staging retained"));
            let staged = fs::read_dir(owned.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".selfhost-stage-")
                })
                .unwrap();
            let backup = fs::read_dir(owned.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".selfhost-backup-")
                })
                .unwrap();
            assert_eq!(
                fs::read_to_string(staged.join("README.md")).unwrap(),
                "replacement"
            );
            assert_eq!(
                fs::read_to_string(backup.join("bundle/README.md")).unwrap(),
                "original"
            );
            verify_owned(&backup.join("bundle")).unwrap();
            if directory {
                assert_eq!(fs::read_dir(&options.output).unwrap().count(), 0);
            } else {
                assert_eq!(fs::read_to_string(&options.output).unwrap(), "foreign");
            }
        }
    }
}
