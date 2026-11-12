//! Private, descriptor-bound publication for operator-only successors.
//! Only public executable/artifact bytes and local ownership records enter here.
use super::*;
use crate::installer_host_fs::{self as host, RenameMode};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(super) struct Directory {
    path: PathBuf,
    file: File,
}

fn identity(m: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn label(name: &str) -> Result<CString> {
    require(
        !name.is_empty()
            && name.len() <= 180
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && name != "."
            && name != "..",
    )?;
    CString::new(name).map_err(|_| REFUSED.into())
}

impl Directory {
    pub(super) fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            path: path.into(),
            file: host::directory(path, REFUSED)?,
        })
    }

    pub(super) fn require(&self) -> Result<()> {
        host::require_directory_binding(&self.path, &self.file, REFUSED)
    }

    pub(super) fn child(&self, name: &str, create: bool) -> Result<Self> {
        self.require()?;
        let name_c = label(name)?;
        if create && unsafe { libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST))?;
        }
        if create {
            self.file.sync_all().map_err(|_| REFUSED)?;
        }
        let result = Self::open(&self.path.join(name))?;
        self.require()?;
        Ok(result)
    }

    pub(super) fn names(&self) -> Result<BTreeSet<String>> {
        self.require()?;
        let names = host::file_names(&self.file, REFUSED)?;
        self.require()?;
        Ok(names)
    }

    fn opened(&self, name: &str, maximum: u64, mode: u32, empty: bool) -> Result<Option<File>> {
        label(name)?;
        self.require()?;
        if !self.names()?.contains(name) {
            return Ok(None);
        }
        let file = host::open_child(&self.file, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
        let m = file.metadata().map_err(|_| REFUSED)?;
        require(
            m.is_file()
                && m.uid() == unsafe { libc::geteuid() }
                && m.nlink() == 1
                && m.mode() & 0o7777 == mode
                && (empty || m.len() > 0)
                && m.len() <= maximum,
        )?;
        self.require()?;
        Ok(Some(file))
    }

    pub(super) fn read(&self, name: &str, maximum: usize, mode: u32) -> Result<Option<Vec<u8>>> {
        self.read_with_empty(name, maximum, mode, false)
    }

    pub(super) fn read_partial(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        require(name.starts_with("partial-"))?;
        self.read_with_empty(name, maximum, 0o600, true)
    }

    fn read_with_empty(
        &self,
        name: &str,
        maximum: usize,
        mode: u32,
        empty: bool,
    ) -> Result<Option<Vec<u8>>> {
        let Some(mut file) = self.opened(name, maximum as u64, mode, empty)? else {
            return Ok(None);
        };
        let before = file.metadata().map_err(|_| REFUSED)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        let after = file.metadata().map_err(|_| REFUSED)?;
        let linked = self
            .opened(name, maximum as u64, mode, empty)?
            .ok_or(REFUSED)?;
        require(
            identity(&before) == identity(&after)
                && identity(&after) == identity(&linked.metadata().map_err(|_| REFUSED)?)
                && bytes.len() as u64 == before.len(),
        )?;
        self.require()?;
        Ok(Some(bytes))
    }

    /// An interrupted inert copy can only be extended when every retained byte
    /// is a prefix of the same authenticated value. Published files never change.
    pub(super) fn publish(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        require(!bytes.is_empty() && bytes.len() <= MAX_RECORD && mode == 0o600)?;
        if let Some(old) = self.read(name, bytes.len(), mode)? {
            require(old == bytes)?;
            return Ok(());
        }
        let temporary = format!("partial-{name}");
        self.require()?;
        let mut file =
            if let Some(mut partial) = self.opened(&temporary, bytes.len() as u64, 0o600, true)? {
                let mut prefix = Vec::new();
                partial.read_to_end(&mut prefix).map_err(|_| REFUSED)?;
                require(bytes.starts_with(&prefix))?;
                let mut output = host::open_child(&self.file, &temporary, libc::O_WRONLY, REFUSED)?;
                require(
                    identity(&partial.metadata().map_err(|_| REFUSED)?)
                        == identity(&output.metadata().map_err(|_| REFUSED)?),
                )?;
                output
                    .seek(SeekFrom::Start(prefix.len() as u64))
                    .map_err(|_| REFUSED)?;
                output
                    .write_all(&bytes[prefix.len()..])
                    .map_err(|_| REFUSED)?;
                output
            } else {
                let mut output = self.create(&temporary)?;
                output.write_all(bytes).map_err(|_| REFUSED)?;
                output
            };
        file.flush()
            .and_then(|_| file.sync_all())
            .map_err(|_| REFUSED)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0)?;
        file.sync_all().map_err(|_| REFUSED)?;
        self.require()?;
        host::rename_at(
            &self.file,
            &label(&temporary)?,
            &self.file,
            &label(name)?,
            RenameMode::NoReplace,
        )
        .map_err(|_| REFUSED)?;
        self.file.sync_all().map_err(|_| REFUSED)?;
        require(self.read(name, bytes.len(), mode)?.as_deref() == Some(bytes))?;
        self.require()
    }

    fn create(&self, name: &str) -> Result<File> {
        let name = label(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0)?;
        use std::os::fd::FromRawFd;
        let file = unsafe { File::from_raw_fd(fd) };
        self.file.sync_all().map_err(|_| REFUSED)?;
        Ok(file)
    }

    pub(super) fn copy_operator(&self, source: &Path, expected: &Operator) -> Result<()> {
        if self.names()?.contains("marty-deploy") {
            return self.verify_operator(expected);
        }
        require(crate::installer_verify::operator_digest(source)? == expected.sha256)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(source)
            .map_err(|_| REFUSED)?;
        let before = input.metadata().map_err(|_| REFUSED)?;
        require(
            before.is_file()
                && before.uid() == unsafe { libc::geteuid() }
                && before.nlink() == 1
                && before.mode() & 0o7777 == 0o700
                && before.len() == expected.size,
        )?;
        let temporary = "partial-marty-deploy";
        let mut output = if self.names()?.contains(temporary) {
            let partial = host::open_child(
                &self.file,
                temporary,
                libc::O_RDONLY | libc::O_NONBLOCK,
                REFUSED,
            )?;
            let metadata = partial.metadata().map_err(|_| REFUSED)?;
            require(
                metadata.is_file()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.nlink() == 1
                    && [0o600, 0o700].contains(&(metadata.mode() & 0o7777))
                    && metadata.len() <= expected.size
                    && (metadata.mode() & 0o7777 != 0o700 || metadata.len() == expected.size),
            )?;
            let output = host::open_child(&self.file, temporary, libc::O_RDWR, REFUSED)?;
            require(
                identity(&partial.metadata().map_err(|_| REFUSED)?)
                    == identity(&output.metadata().map_err(|_| REFUSED)?),
            )?;
            output
        } else {
            self.create(temporary)?
        };
        let retained = output.metadata().map_err(|_| REFUSED)?.len();
        let mut offset = 0u64;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        while offset < expected.size {
            let maximum = usize::try_from((expected.size - offset).min(buffer.len() as u64))
                .map_err(|_| REFUSED)?;
            let count = input.read(&mut buffer[..maximum]).map_err(|_| REFUSED)?;
            require(count > 0)?;
            digest.update(&buffer[..count]);
            let prefix = usize::try_from(retained.saturating_sub(offset).min(count as u64))
                .map_err(|_| REFUSED)?;
            if prefix > 0 {
                let mut existing = vec![0; prefix];
                output.read_exact(&mut existing).map_err(|_| REFUSED)?;
                require(existing == buffer[..prefix])?;
            }
            output
                .write_all(&buffer[prefix..count])
                .map_err(|_| REFUSED)?;
            offset += count as u64;
        }
        require(
            input.read(&mut buffer[..1]).map_err(|_| REFUSED)? == 0
                && format!("{:x}", digest.finalize()) == expected.sha256
                && identity(&before) == identity(&input.metadata().map_err(|_| REFUSED)?)
                && identity(&before)
                    == identity(&std::fs::symlink_metadata(source).map_err(|_| REFUSED)?),
        )?;
        output.sync_all().map_err(|_| REFUSED)?;
        require(unsafe { libc::fchmod(output.as_raw_fd(), 0o700) } == 0)?;
        output.sync_all().map_err(|_| REFUSED)?;
        self.require()?;
        host::rename_at(
            &self.file,
            &label(temporary)?,
            &self.file,
            &label("marty-deploy")?,
            RenameMode::NoReplace,
        )
        .map_err(|_| REFUSED)?;
        self.file.sync_all().map_err(|_| REFUSED)?;
        self.verify_operator(expected)
    }

    pub(super) fn verify_operator(&self, operator: &Operator) -> Result<()> {
        self.require()?;
        let path = self.path.join("marty-deploy");
        require(
            crate::installer_verify::operator_digest(&path)? == operator.sha256
                && std::fs::symlink_metadata(&path).map_err(|_| REFUSED)?.len() == operator.size,
        )?;
        self.require()
    }
}

/// The old selector survives exchange until its inode and bytes are proved.
/// The owning LockedMaintenance poisons itself on any uncertain publication.
pub(super) fn replace_selector(
    evidence: &Directory,
    expected: Option<&[u8]>,
    next: &[u8],
    sequence: u64,
    mut boundary: impl FnMut(u8) -> Result<()>,
) -> Result<()> {
    require(!next.is_empty() && next.len() <= MAX_RECORD)?;
    let old = evidence.read(SELECTOR, MAX_RECORD, 0o600)?;
    require(old.as_deref() == expected)?;
    let old_file = evidence.opened(SELECTOR, MAX_RECORD as u64, 0o600, false)?;
    let temporary = format!("operator-upgrade-{sequence:04}-selector.tmp");
    evidence.publish(&temporary, next, 0o600)?;
    let next_file = evidence
        .opened(&temporary, MAX_RECORD as u64, 0o600, false)?
        .ok_or(REFUSED)?;
    boundary(1)?;
    evidence.require()?;
    require(evidence.read(SELECTOR, MAX_RECORD, 0o600)?.as_deref() == expected)?;
    if let Some(held) = &old_file {
        let current = evidence
            .opened(SELECTOR, MAX_RECORD as u64, 0o600, false)?
            .ok_or(REFUSED)?;
        require(
            identity(&held.metadata().map_err(|_| REFUSED)?)
                == identity(&current.metadata().map_err(|_| REFUSED)?),
        )?;
    }
    host::rename_at(
        &evidence.file,
        &label(&temporary)?,
        &evidence.file,
        &label(SELECTOR)?,
        if old_file.is_some() {
            RenameMode::Exchange
        } else {
            RenameMode::NoReplace
        },
    )
    .map_err(|_| REFUSED)?;
    evidence.file.sync_all().map_err(|_| REFUSED)?;
    boundary(2)?;
    let published = evidence
        .opened(SELECTOR, MAX_RECORD as u64, 0o600, false)?
        .ok_or(REFUSED)?;
    require(
        identity(&published.metadata().map_err(|_| REFUSED)?)
            == identity(&next_file.metadata().map_err(|_| REFUSED)?),
    )?;
    require(evidence.read(SELECTOR, MAX_RECORD, 0o600)?.as_deref() == Some(next))?;
    if let Some(held) = old_file {
        let displaced = evidence
            .opened(&temporary, MAX_RECORD as u64, 0o600, false)?
            .ok_or(REFUSED)?;
        require(
            identity(&displaced.metadata().map_err(|_| REFUSED)?)
                == identity(&held.metadata().map_err(|_| REFUSED)?),
        )?;
        require(evidence.read(&temporary, MAX_RECORD, 0o600)?.as_deref() == expected)?;
        require(
            unsafe { libc::unlinkat(evidence.file.as_raw_fd(), label(&temporary)?.as_ptr(), 0) }
                == 0,
        )?;
        evidence.file.sync_all().map_err(|_| REFUSED)?;
    }
    evidence.require()
}

pub(super) fn reconcile_selector_temporary(
    evidence: &Directory,
    sequence: u64,
    previous: Option<&[u8]>,
) -> Result<()> {
    let temporary = format!("operator-upgrade-{sequence:04}-selector.tmp");
    if let Some(bytes) = evidence.read(&temporary, MAX_RECORD, 0o600)? {
        require(Some(bytes.as_slice()) == previous)?;
        require(
            unsafe { libc::unlinkat(evidence.file.as_raw_fd(), label(&temporary)?.as_ptr(), 0) }
                == 0,
        )?;
        evidence.file.sync_all().map_err(|_| REFUSED)?;
    }
    evidence.require()
}
