//! Atomic no-replace directory moves. Never fall back to overwriting rename.
use std::{io, path::Path};

pub(super) fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let encode = |path: &Path| -> io::Result<Vec<u16>> {
            let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
            if value.contains(&0) {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            value.push(0);
            Ok(value)
        };
        let source = encode(source)?;
        let destination = encode(destination)?;
        // SAFETY: both vectors are live, NUL-terminated UTF-16 paths. Flags=0
        // specifically excludes MOVEFILE_REPLACE_EXISTING and cross-volume copy.
        let moved = unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                0,
            )
        };
        if moved == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox",
        windows
    )))]
    {
        let _ = (source, destination);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn appeared_foreign_file_and_empty_directory_are_never_replaced() {
        for directory in [false, true] {
            let owned = tempfile::tempdir().unwrap();
            let source = owned.path().join("staged");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("new"), "staged data").unwrap();
            let target = owned.path().join("appeared");
            if directory {
                fs::create_dir(&target).unwrap();
            } else {
                fs::write(&target, "foreign").unwrap();
            }
            assert!(rename_noreplace(&source, &target).is_err());
            assert_eq!(
                fs::read_to_string(source.join("new")).unwrap(),
                "staged data"
            );
            if directory {
                assert_eq!(fs::read_dir(target).unwrap().count(), 0);
            } else {
                assert_eq!(fs::read_to_string(target).unwrap(), "foreign");
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn appeared_foreign_symlink_is_not_followed_or_replaced() {
        use std::os::unix::fs::symlink;
        let owned = tempfile::tempdir().unwrap();
        let source = owned.path().join("staged");
        fs::create_dir(&source).unwrap();
        let foreign = owned.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        let target = owned.path().join("appeared");
        symlink(&foreign, &target).unwrap();
        assert!(rename_noreplace(&source, &target).is_err());
        assert!(fs::symlink_metadata(target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(source.is_dir());
    }
}
