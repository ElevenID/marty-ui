//! Private file custody for the existing rootless installer setup-job envelope.
//! Host Compose admission owns UID mapping, image and mount authorization.
//! No environment or caller path selects an input, database or output.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use super::{need, ApiKey, BootstrapError, Result, KEY_FILE};

const REQUEST: &str = "/input/organization-bootstrap-request.json";
const INSTALLATION: &str = "/input/installation.json";
const SESSION: &str = "/input/compose-session.json";
const PASSWORD: &str = "/input/marty-db-password";
const OUTPUT: &str = "/output";
const OUTPUT_NAMES: &[&str] = &[
    "issue-intent.json",
    "api-key",
    "issued.json",
    "failed.json",
    "revoke-intent.json",
    "revoked.json",
];

pub(super) struct Inputs {
    pub request: Vec<u8>,
    pub installation: Vec<u8>,
    pub session: Vec<u8>,
    pub database_url: String,
}

fn process_owner(status: &str) -> Result<u32> {
    let values = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
    need(
        values("NoNewPrivs:").map(str::trim) == Some("1"),
        "setup process refused",
    )?;
    let ids = values("Uid:")
        .ok_or(BootstrapError("setup process refused"))?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| BootstrapError("setup process refused"))?;
    need(
        ids.len() == 4 && ids.iter().all(|id| *id == ids[0]),
        "setup process refused",
    )?;
    Ok(ids[0])
}

fn mounted(mountinfo: &str, path: &str, writable: bool) -> Result<()> {
    let entries = mountinfo
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() > 6 && fields[4] == path).then(|| fields[5])
        })
        .collect::<Vec<_>>();
    need(entries.len() == 1, "setup mount refused")?;
    let flags = entries[0].split(',').collect::<BTreeSet<_>>();
    need(
        flags.contains(if writable { "rw" } else { "ro" })
            && !flags.contains(if writable { "ro" } else { "rw" }),
        "setup mount refused",
    )
}

fn setup_envelope(status: &str, mountinfo: &str) -> Result<u32> {
    let uid = process_owner(status)?;
    mounted(mountinfo, "/", false)?;
    for path in [REQUEST, INSTALLATION, SESSION, PASSWORD] {
        mounted(mountinfo, path, false)?;
    }
    mounted(mountinfo, OUTPUT, true)?;
    Ok(uid)
}

fn regular(path: &Path, uid: u32, maximum: u64, scalar: bool) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| BootstrapError("input unavailable"))?;
    let before = file
        .metadata()
        .map_err(|_| BootstrapError("input unavailable"))?;
    let mode = before.mode() & 0o7777;
    need(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= maximum
            && (matches!(mode, 0o400 | 0o600) || (scalar && mode == 0o444)),
        "input custody refused",
    )?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BootstrapError("input unavailable"))?;
    let after = file
        .metadata()
        .map_err(|_| BootstrapError("input unavailable"))?;
    need(
        bytes.len() as u64 == before.len()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "input changed",
    )?;
    Ok(bytes)
}

impl Inputs {
    pub fn load() -> Result<Self> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|_| BootstrapError("setup process unavailable"))?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")
            .map_err(|_| BootstrapError("setup mounts unavailable"))?;
        let uid = setup_envelope(&status, &mountinfo)?;
        let request = regular(Path::new(REQUEST), uid, 16_384, false)?;
        let installation = regular(Path::new(INSTALLATION), uid, 65_536, false)?;
        let session = regular(Path::new(SESSION), uid, 8 * 1024 * 1024, false)?;
        let password = regular(Path::new(PASSWORD), uid, 4_096, true)?;
        let password = std::str::from_utf8(&password)
            .map_err(|_| BootstrapError("database credential refused"))?
            .trim_end_matches(['\r', '\n']);
        need(
            !password.is_empty() && password.bytes().all(|b| !b.is_ascii_control()),
            "database credential refused",
        )?;
        let mut url = url::Url::parse("postgresql://marty@postgres:5432/marty")
            .map_err(|_| BootstrapError("database configuration refused"))?;
        url.set_password(Some(password))
            .map_err(|()| BootstrapError("database credential refused"))?;
        // PostgreSQL session bounds, not schema or authorization changes.
        url.query_pairs_mut()
            .append_pair("options", "-c statement_timeout=15000 -c lock_timeout=5000");
        Ok(Self {
            request,
            installation,
            session,
            database_url: url.to_string(),
        })
    }
}

pub(super) struct Output {
    path: PathBuf,
    directory: File,
    uid: u32,
}

impl Output {
    pub fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| BootstrapError("output unavailable"))?;
        let metadata = directory
            .metadata()
            .map_err(|_| BootstrapError("output unavailable"))?;
        let uid = process_owner(
            &fs::read_to_string("/proc/self/status")
                .map_err(|_| BootstrapError("setup process unavailable"))?,
        )?;
        need(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700,
            "output custody refused",
        )?;
        let output = Self {
            path: path.into(),
            directory,
            uid,
        };
        output.check()?;
        for entry in
            fs::read_dir(output.held()).map_err(|_| BootstrapError("output unavailable"))?
        {
            let name = entry
                .map_err(|_| BootstrapError("output unavailable"))?
                .file_name();
            need(
                name.to_str()
                    .is_some_and(|value| OUTPUT_NAMES.contains(&value)),
                "foreign output refused",
            )?;
        }
        Ok(output)
    }

    fn held(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    fn check(&self) -> Result<()> {
        let held = self
            .directory
            .metadata()
            .map_err(|_| BootstrapError("output unavailable"))?;
        let current =
            fs::symlink_metadata(&self.path).map_err(|_| BootstrapError("output unavailable"))?;
        need(
            current.is_dir()
                && current.dev() == held.dev()
                && current.ino() == held.ino()
                && current.uid() == self.uid
                && current.mode() & 0o7777 == 0o700,
            "output binding changed",
        )
    }

    fn entry(&self, name: &str) -> Result<PathBuf> {
        need(OUTPUT_NAMES.contains(&name), "output name refused")?;
        self.check()?;
        Ok(self.held().join(name))
    }

    pub fn require_empty(&self) -> Result<()> {
        self.check()?;
        need(
            fs::read_dir(self.held())
                .map_err(|_| BootstrapError("output unavailable"))?
                .next()
                .is_none(),
            "operation already started",
        )
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        need(
            !bytes.is_empty() && bytes.len() <= 65_536,
            "output size refused",
        )?;
        let path = self.entry(name)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| BootstrapError("operation already started or output unavailable"))?;
        self.directory
            .sync_all()
            .map_err(|_| BootstrapError("output durability uncertain"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| self.directory.sync_all())
            .map_err(|_| BootstrapError("output durability uncertain"))?;
        self.check()
    }

    pub fn optional(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.entry(name)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(BootstrapError("output unavailable")),
            Ok(_) => regular(&path, self.uid, 65_536, false).map(Some),
        }
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        self.optional(name)?
            .ok_or(BootstrapError("recorded output absent"))
    }

    pub fn remove_key_if_matching(&self, key: &ApiKey) -> Result<()> {
        if let Some(bytes) = self.optional(KEY_FILE)? {
            let raw = std::str::from_utf8(&bytes)
                .map_err(|_| BootstrapError("credential output differs"))?;
            need(key.verify(raw), "credential output differs")?;
            fs::remove_file(self.entry(KEY_FILE)?)
                .and_then(|()| self.directory.sync_all())
                .map_err(|_| BootstrapError("credential removal uncertain"))?;
        }
        self.check()
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub fn open(path: &Path) -> Output {
        let directory = File::open(path).unwrap();
        let uid = directory.metadata().unwrap().uid();
        Output {
            path: path.into(),
            directory,
            uid,
        }
    }

    pub fn envelope(status: &str, mounts: &str) -> Result<u32> {
        setup_envelope(status, mounts)
    }

    pub fn read(path: &Path, uid: u32) -> Result<Vec<u8>> {
        regular(path, uid, 4096, false)
    }
}
