//! Private operator inputs and exclusively created credential outputs.
use crate::operator::{Result, REFUSAL};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MAX_INPUT: u64 = 64 * 1024;

pub(crate) fn private_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(REFUSAL);
    }
    let info = fs::symlink_metadata(path).map_err(|_| REFUSAL)?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o7777 != 0o700 {
            return Err(REFUSAL);
        }
    }
    #[cfg(not(unix))]
    {
        Err(REFUSAL)
    }
    #[cfg(unix)]
    fs::canonicalize(path).map_err(|_| REFUSAL)
}

pub(crate) fn private_file(path: &Path) -> Result<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| REFUSAL)?;
    let info = file.metadata().map_err(|_| REFUSAL)?;
    if !info.is_file() || info.len() > MAX_INPUT {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err(REFUSAL);
        }
    }
    let mut value = String::new();
    file.take(MAX_INPUT + 1)
        .read_to_string(&mut value)
        .map_err(|_| REFUSAL)?;
    if value.len() as u64 > MAX_INPUT {
        return Err(REFUSAL);
    }
    Ok(value)
}

pub(crate) fn write_private(path: &Path, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.is_ascii()
        || value.contains(['\r', '\n'])
    {
        return Err(REFUSAL);
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| REFUSAL)?;
    file.write_all(value.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSAL)
}
