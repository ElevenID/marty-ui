//! Supplemental live custody fence for read-only installer transactions.
//! Metadata/content/path checks remain required. This detects observed changes
//! even when a filesystem clock gives a change-and-revert the same timestamp.
#![cfg(target_os = "linux")]

use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    sync::Mutex,
};

pub(crate) struct ChangeWatch {
    events: File,
    rejected: Mutex<bool>,
}
impl ChangeWatch {
    /// Start before capturing the metadata baseline. Watches bind the held
    /// inode through genuine procfs; no caller path is followed or modified.
    pub(crate) fn new(held: &File) -> Result<Self, ()> {
        let proc = File::open("/proc/self/fd").map_err(|_| ())?;
        let mut info: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0
            || info.f_type as i64 != 0x9fa0
        {
            return Err(());
        }
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(());
        }
        let events = unsafe { File::from_raw_fd(fd) };
        let path = CString::new(format!("/proc/self/fd/{}", held.as_raw_fd())).map_err(|_| ())?;
        let mask = libc::IN_ATTRIB
            | libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE
            | libc::IN_MOVE_SELF
            | libc::IN_DELETE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO;
        // Follow only this kernel-owned descriptor link, not a user pathname.
        if unsafe { libc::inotify_add_watch(events.as_raw_fd(), path.as_ptr(), mask) } < 0 {
            return Err(());
        }
        Ok(Self {
            events,
            rejected: Mutex::new(false),
        })
    }

    /// Any queued change, overflow, invalidated watch or observation error
    /// permanently refuses this guard. Reading cannot turn a retry into success.
    pub(crate) fn unchanged(&self) -> Result<(), ()> {
        let mut rejected = self.rejected.lock().map_err(|_| ())?;
        if *rejected {
            return Err(());
        }
        let mut buffer = [0u8; 4096];
        let count = unsafe {
            libc::read(
                self.events.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            return Ok(());
        }
        *rejected = true;
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Read, os::unix::fs::PermissionsExt};

    #[test]
    fn reads_preserve_custody_but_attribute_cycles_permanently_refuse_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic-public-proof");
        fs::write(&path, b"synthetic proof").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = File::open(&path).unwrap();
        let watch = ChangeWatch::new(&file).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(watch.unchanged().is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(watch.unchanged().is_err());
        assert!(watch.unchanged().is_err());
    }

    #[test]
    fn moved_back_directory_cannot_restore_its_live_custody() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("delivered");
        let moved = temp.path().join("moved");
        fs::create_dir(&path).unwrap();
        let file = File::open(&path).unwrap();
        let watch = ChangeWatch::new(&file).unwrap();
        assert!(watch.unchanged().is_ok());
        fs::rename(&path, &moved).unwrap();
        fs::rename(&moved, &path).unwrap();
        assert!(watch.unchanged().is_err());
        assert!(watch.unchanged().is_err());
    }
}
