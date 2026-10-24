//! Private operator inputs and exclusively created credential outputs.
use crate::operator::{Result, REFUSAL};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MAX_INPUT: u64 = 64 * 1024;

/// Bounded byte-preserving public certificates/scoped secrets, never key material.
/// Separate from private_file: generation files may intentionally be mode 0444.
pub(crate) fn generation_file(path: &Path, allow_empty: bool) -> Result<(Vec<u8>, u32)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    if fs::symlink_metadata(path)
        .map_err(|_| REFUSAL)?
        .file_type()
        .is_symlink()
    {
        return Err(REFUSAL);
    }
    let file = options.open(path).map_err(|_| REFUSAL)?;
    let info = file.metadata().map_err(|_| REFUSAL)?;
    if !info.is_file() || info.len() > MAX_INPUT {
        return Err(REFUSAL);
    }
    let mut value = Vec::new();
    file.take(MAX_INPUT + 1)
        .read_to_end(&mut value)
        .map_err(|_| REFUSAL)?;
    if value.len() as u64 != info.len()
        || value.len() as u64 > MAX_INPUT
        || (!allow_empty && value.is_empty())
        || value.contains(&0)
        || value.windows(11).any(|s| s == b"PRIVATE KEY")
    {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok((value, info.permissions().mode() & 0o7777))
    }
    #[cfg(not(unix))]
    {
        Ok((value, 0))
    }
}

/// Open exclusively at 0600, then preserve the active generation's supported mode.
/// The caller owns rollback only after this function has created its file.
pub(crate) fn generation_output(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|_| REFUSAL)
}

pub(crate) fn finish_generation(file: &mut fs::File, value: &[u8], mode: u32) -> Result<()> {
    file.write_all(value)
        .and_then(|_| file.flush())
        .map_err(|_| REFUSAL)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| REFUSAL)?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        Err(REFUSAL)
    }
    #[cfg(unix)]
    file.sync_all().map_err(|_| REFUSAL)
}

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
