//! Exact private-file custody for one authenticated candidate transaction.
//! Public proof digests are useful only after the fixed verifier succeeds;
//! neither this snapshot nor its later historical digest check authenticates
//! a signature on its own.
use super::{release, require, Result, VerificationTools, REFUSED};
use crate::{installer_host_fs as fs, installer_state::InstallerState};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq, Eq)]
struct Binding {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Debug, PartialEq, Eq)]
struct DirectoryBinding {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl DirectoryBinding {
    fn observe(file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o700,
        )?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}
impl Binding {
    fn observe(metadata: Metadata, maximum: usize) -> Result<Self> {
        Self::observe_mode(metadata, maximum, 0o600)
    }
    fn observe_mode(metadata: Metadata, maximum: usize, mode: u32) -> Result<Self> {
        require(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == mode
                && metadata.nlink() == 1
                && metadata.len() > 0
                && metadata.len() <= maximum as u64,
        )?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// Retain a large public payload's inode and private parent throughout a read-only
/// observation. Hash through that descriptor; never load executable/bundle bytes
/// into an evidence record or accept a same-byte inode replacement.
pub(super) struct HeldAsset {
    path: PathBuf,
    parent: File,
    parent_binding: DirectoryBinding,
    file: File,
    binding: Binding,
    digest: String,
    mode: u32,
    deadline: std::time::Instant,
}
impl HeldAsset {
    pub(super) fn open(
        path: &Path,
        digest: &str,
        size: u64,
        executable: bool,
        deadline: std::time::Instant,
    ) -> Result<Self> {
        require(super::hex(digest, 64) && (1..=536_870_912).contains(&size))?;
        let parent_path = path.parent().ok_or(REFUSED)?;
        crate::installer_runtime::private_parent(parent_path)?;
        let parent = fs::directory(parent_path, REFUSED)?;
        let parent_binding = DirectoryBinding::observe(&parent)?;
        let name = path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
        let file = fs::open_child(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
        let mode = if executable { 0o700 } else { 0o600 };
        let binding =
            Binding::observe_mode(file.metadata().map_err(|_| REFUSED)?, size as usize, mode)?;
        require(binding.length == size)?;
        let held = Self {
            path: path.into(),
            parent,
            parent_binding,
            file,
            binding,
            digest: digest.into(),
            mode,
            deadline,
        };
        held.check()?;
        Ok(held)
    }
    pub(super) fn check(&self) -> Result<()> {
        use sha2::{Digest, Sha256};
        let parent_path = self.path.parent().ok_or(REFUSED)?;
        crate::installer_runtime::private_parent(parent_path)?;
        fs::require_directory_binding(parent_path, &self.parent, REFUSED)?;
        require(DirectoryBinding::observe(&self.parent)? == self.parent_binding)?;
        let named = fs::open_child(
            &self.parent,
            self.path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or(REFUSED)?,
            libc::O_RDONLY | libc::O_NONBLOCK,
            REFUSED,
        )?;
        for file in [&self.file, &named] {
            require(
                Binding::observe_mode(
                    file.metadata().map_err(|_| REFUSED)?,
                    self.binding.length as usize,
                    self.mode,
                )? == self.binding,
            )?;
        }
        let mut hash = Sha256::new();
        let mut offset = 0;
        let mut buffer = [0u8; 65_536];
        while offset < self.binding.length {
            require(std::time::Instant::now() < self.deadline)?;
            let length = (self.binding.length - offset).min(buffer.len() as u64) as usize;
            self.file
                .read_exact_at(&mut buffer[..length], offset)
                .map_err(|_| REFUSED)?;
            hash.update(&buffer[..length]);
            offset += length as u64;
        }
        require(format!("{:x}", hash.finalize()) == self.digest)?;
        require(
            Binding::observe_mode(
                self.file.metadata().map_err(|_| REFUSED)?,
                self.binding.length as usize,
                self.mode,
            )? == self.binding,
        )?;
        fs::require_directory_binding(parent_path, &self.parent, REFUSED)?;
        require(DirectoryBinding::observe(&self.parent)? == self.parent_binding)
    }
}

pub(super) struct HeldInput {
    path: PathBuf,
    parent: File,
    parent_binding: DirectoryBinding,
    file: File,
    binding: Binding,
    maximum: usize,
    bytes: Vec<u8>,
}
impl HeldInput {
    pub(super) fn open(path: &Path, maximum: usize) -> Result<Self> {
        require(path.is_absolute() && (1..=1_048_576).contains(&maximum))?;
        let parent_path = path.parent().ok_or(REFUSED)?;
        crate::installer_runtime::private_parent(parent_path)?;
        let parent = fs::directory(parent_path, REFUSED)?;
        let parent_binding = DirectoryBinding::observe(&parent)?;
        let name = path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
        let file = fs::open_child(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
        let binding = Binding::observe(file.metadata().map_err(|_| REFUSED)?, maximum)?;
        let bytes = Self::read(&file, binding.length as usize)?;
        let result = Self {
            path: path.into(),
            parent,
            parent_binding,
            file,
            binding,
            maximum,
            bytes,
        };
        result.check()?;
        Ok(result)
    }
    fn read(file: &File, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        file.read_exact_at(&mut bytes, 0).map_err(|_| REFUSED)?;
        let mut extra = [0];
        require(
            file.read_at(&mut extra, length as u64)
                .map_err(|_| REFUSED)?
                == 0,
        )?;
        Ok(bytes)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn check(&self) -> Result<()> {
        let parent = self.path.parent().ok_or(REFUSED)?;
        crate::installer_runtime::private_parent(parent)?;
        fs::require_directory_binding(parent, &self.parent, REFUSED)?;
        require(DirectoryBinding::observe(&self.parent)? == self.parent_binding)?;
        let name = self
            .path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(REFUSED)?;
        let named = fs::open_child(
            &self.parent,
            name,
            libc::O_RDONLY | libc::O_NONBLOCK,
            REFUSED,
        )?;
        for file in [&self.file, &named] {
            require(
                Binding::observe(file.metadata().map_err(|_| REFUSED)?, self.maximum)?
                    == self.binding
                    && Self::read(file, self.bytes.len())? == self.bytes
                    && Binding::observe(file.metadata().map_err(|_| REFUSED)?, self.maximum)?
                        == self.binding,
            )?;
        }
        fs::require_directory_binding(parent, &self.parent, REFUSED)?;
        require(DirectoryBinding::observe(&self.parent)? == self.parent_binding)
    }
}

pub(super) struct SignedSubject {
    source: PathBuf,
    name: String,
    files: BTreeMap<String, HeldInput>,
}

pub(super) struct HostingInput {
    directory_path: PathBuf,
    directory: File,
    input: Option<HeldInput>,
    roots: Option<HeldInput>,
    binding: Option<release::CandidateHosting>,
}
impl HostingInput {
    const ROOTS_INPUT: &'static str = "acme-staging-roots.pem";
    pub(super) fn open(
        directory_path: &Path,
        binding: Option<&release::CandidateHosting>,
    ) -> Result<Self> {
        crate::installer_runtime::private_parent(directory_path)?;
        let directory = fs::directory(directory_path, REFUSED)?;
        let input = binding
            .map(|_| {
                HeldInput::open(
                    &directory_path.join(crate::installer_hosting::SOURCE),
                    release::MAX_CANDIDATE_HOSTING,
                )
            })
            .transpose()?;
        let roots = binding
            .filter(|v| v.staging_trust.is_some())
            .map(|_| HeldInput::open(&directory_path.join(Self::ROOTS_INPUT), 65_536))
            .transpose()?;
        if let Some(input) = &input {
            require(
                crate::installer_hosting::candidate_binding(
                    input.bytes(),
                    roots.as_ref().map(HeldInput::bytes),
                )? == *binding.ok_or(REFUSED)?,
            )?;
        }
        let result = Self {
            directory_path: directory_path.into(),
            directory,
            input,
            roots,
            binding: binding.cloned(),
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn binding(&self) -> Option<release::CandidateHosting> {
        self.binding.clone()
    }
    pub(super) fn check(&self) -> Result<()> {
        crate::installer_runtime::private_parent(&self.directory_path)?;
        fs::require_directory_binding(&self.directory_path, &self.directory, REFUSED)?;
        for (name, input) in [
            (crate::installer_hosting::SOURCE, &self.input),
            (Self::ROOTS_INPUT, &self.roots),
        ] {
            if let Some(input) = input {
                input.check()?;
            } else {
                match std::fs::symlink_metadata(self.directory_path.join(name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(REFUSED.into()),
                }
            }
        }
        fs::require_directory_binding(&self.directory_path, &self.directory, REFUSED)
    }
    pub(super) fn prepare(&self) -> Result<crate::installer_hosting::Prepared> {
        self.check()?;
        let prepared =
            crate::installer_hosting::prepare(self.input.as_ref().map(HeldInput::path), None)?;
        if let Some(binding) = &self.binding {
            require(prepared.input_sha256() == binding.input_sha256)?;
        }
        self.check()?;
        Ok(prepared)
    }
    pub(super) fn select(&self, state: &mut InstallerState) -> Result<()> {
        let prepared = self.prepare()?;
        let selection = crate::installer_hosting::select(prepared, state)?;
        if let Some(binding) = &self.binding {
            require(selection.source_sha256() == binding.input_sha256)?;
        }
        if let Some(roots) = &self.roots {
            state.write_evidence(crate::installer_command::STAGING_ROOTS, roots.bytes())?;
            state.with_inspection(|view| {
                require(
                    view.read_evidence(crate::installer_command::STAGING_ROOTS)? == roots.bytes(),
                )
            })?;
        }
        self.check()
    }
}
impl SignedSubject {
    pub(super) fn open(source: &Path, name: &str) -> Result<Self> {
        require(matches!(
            name,
            "installer-candidate-authorization.json"
                | "installer-controller-consumption.json"
                | "installer-inventory.json"
        ))?;
        let mut files = BTreeMap::new();
        for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
            let mut path = source.as_os_str().to_owned();
            path.push(suffix);
            files.insert(
                format!("{name}{suffix}"),
                HeldInput::open(
                    Path::new(&path),
                    if suffix.is_empty() { 65_536 } else { 1_048_576 },
                )?,
            );
        }
        Ok(Self {
            source: source.into(),
            name: name.into(),
            files,
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        self.files[&self.name].bytes()
    }
    pub(super) fn check(&self) -> Result<()> {
        for file in self.files.values() {
            file.check()?;
        }
        Ok(())
    }
    pub(super) fn verify(
        &self,
        tools: &VerificationTools,
        workflow: &str,
        source: &str,
        run: u64,
        attempt: u64,
    ) -> Result<()> {
        self.check()?;
        let verified = tools.verify(&self.source, workflow, source, run, attempt)?;
        self.check()?;
        require(verified == release::sha256(self.bytes()))
    }
    pub(super) fn digests(&self) -> Result<BTreeMap<String, String>> {
        self.check()?;
        Ok(self
            .files
            .iter()
            .map(|(name, file)| (name.clone(), release::sha256(file.bytes())))
            .collect())
    }
    pub(super) fn persist(&self, state: &mut InstallerState) -> Result<()> {
        self.check()?;
        for (name, file) in &self.files {
            file.check()?;
            state.write_evidence(name, file.bytes())?;
            file.check()?;
        }
        state.with_inspection(|view| {
            for (name, file) in &self.files {
                require(view.read_evidence(name)? == file.bytes())?;
            }
            view.require_unchanged()
        })?;
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn held_candidate_files_refuse_inode_content_permission_and_parent_replacement() {
        for mutation in [
            "same-bytes",
            "different-bytes",
            "mode-cycle",
            "symlink",
            "parent",
            "parent-roundtrip",
        ] {
            let outer = tempfile::tempdir().unwrap();
            std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let parent = outer.path().join("grants");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = parent.join("proof.json");
            std::fs::write(&path, b"public proof").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let held = HeldInput::open(&path, 100).unwrap();
            held.check().unwrap();
            match mutation {
                "same-bytes" => {
                    std::fs::rename(&path, parent.join("old")).unwrap();
                    std::fs::write(&path, b"public proof").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                "different-bytes" => std::fs::write(&path, b"changed proof").unwrap(),
                "mode-cycle" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                "symlink" => {
                    std::fs::rename(&path, parent.join("old")).unwrap();
                    symlink("old", &path).unwrap();
                }
                "parent" => {
                    std::fs::rename(&parent, outer.path().join("old")).unwrap();
                    std::fs::create_dir(&parent).unwrap();
                    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                "parent-roundtrip" => {
                    std::fs::rename(&parent, outer.path().join("old")).unwrap();
                    std::fs::rename(outer.path().join("old"), &parent).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(held.check().is_err(), "accepted {mutation}");
        }
    }
}
