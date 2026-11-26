//! Local mutation observation for already pinned candidate/delivery inodes.
//!
//! Timestamp resolution cannot establish that a permission or rename round trip
//! did not happen. Keep kernel event observation alongside the existing content,
//! metadata and name-to-descriptor checks; this is not an atomic tree snapshot
//! or a substitute for excluding concurrent writers. Inotify has documented
//! filesystem/mmap limitations, so no broader mutation-completeness claim is made.
#![cfg(target_os = "linux")]

use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    sync::Mutex,
};

const OWN_MUTATION: u32 = libc::IN_ATTRIB | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF;
const ENTRIES_MUTATION: u32 =
    libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
const LOST: u32 = libc::IN_Q_OVERFLOW | libc::IN_IGNORED | libc::IN_UNMOUNT;
const HEADER: usize = 16;

#[derive(Clone, Copy)]
enum Kind {
    File,
    Directory,
}

struct State {
    events: File,
    descriptor: i32,
    invalid: bool,
}

pub(crate) struct CustodyWatch {
    state: Mutex<State>,
    kind: Kind,
}

fn refused() -> io::Error {
    io::Error::other("custody observation changed or unavailable")
}

impl CustodyWatch {
    pub(crate) fn file(file: &File) -> io::Result<Self> {
        Self::open(file, Kind::File)
    }

    pub(crate) fn directory(file: &File) -> io::Result<Self> {
        Self::open(file, Kind::Directory)
    }

    fn open(file: &File, kind: Kind) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !match kind {
            Kind::File => metadata.is_file(),
            Kind::Directory => metadata.is_dir(),
        } {
            return Err(refused());
        }
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // File owns this new descriptor even if subsequent watch admission fails.
        let events = unsafe { File::from_raw_fd(fd) };
        // Follow only this process's pinned FD, never a mutable caller pathname.
        let path =
            CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| refused())?;
        let mask = OWN_MUTATION
            | match kind {
                Kind::File => libc::IN_MODIFY | libc::IN_CLOSE_WRITE,
                Kind::Directory => ENTRIES_MUTATION | libc::IN_ONLYDIR,
            };
        let descriptor =
            unsafe { libc::inotify_add_watch(events.as_raw_fd(), path.as_ptr(), mask) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            state: Mutex::new(State {
                events,
                descriptor,
                invalid: false,
            }),
            kind,
        })
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        // Serialize draining and sticky invalidation. A second checker must not
        // observe an empty queue while the first checker is handling a change.
        let mut state = self.state.lock().map_err(|_| refused())?;
        if state.invalid {
            return Err(refused());
        }
        let result = self.check_queue(&state);
        if result.is_err() {
            state.invalid = true;
        }
        result
    }

    fn check_queue(&self, state: &State) -> io::Result<()> {
        let mut buffer = [0u8; 4096];
        // Bounded even if another writer continuously generates irrelevant
        // child-attribute events. Failure to finish observation refuses custody.
        for _ in 0..4 {
            let count = unsafe {
                libc::read(
                    state.events.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock => return Ok(()),
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(error),
                }
            }
            if count == 0 || changed(&buffer[..count as usize], state.descriptor, self.kind)? {
                return Err(refused());
            }
        }
        Err(refused())
    }
}

fn changed(bytes: &[u8], descriptor: i32, kind: Kind) -> io::Result<bool> {
    let mut offset = 0usize;
    let mut mutation = false;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset.checked_add(HEADER).ok_or_else(refused)?)
            .ok_or_else(refused)?;
        let wd = i32::from_ne_bytes(header[0..4].try_into().map_err(|_| refused())?);
        let mask = u32::from_ne_bytes(header[4..8].try_into().map_err(|_| refused())?);
        let length = u32::from_ne_bytes(header[12..16].try_into().map_err(|_| refused())?) as usize;
        offset = offset
            .checked_add(HEADER)
            .and_then(|value| value.checked_add(length))
            .filter(|value| *value <= bytes.len())
            .ok_or_else(refused)?;
        if mask & LOST != 0 || wd != descriptor {
            return Err(refused());
        }
        mutation |= match kind {
            Kind::File => true,
            // A child's chmod does not change its parent's metadata/inventory.
            // Keep that distinction while observing the directory inode itself
            // and every entry addition/removal/rename, including round trips.
            Kind::Directory => length == 0 || mask & !libc::IN_ISDIR != libc::IN_ATTRIB,
        };
    }
    Ok(mutation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn permission_and_content_round_trips_are_sticky_without_clock_delays() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proof");
        fs::write(&path, b"public fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for content in [false, true] {
            let file = File::open(&path).unwrap();
            let watch = CustodyWatch::file(&file).unwrap();
            watch.check().unwrap();
            if content {
                fs::write(&path, b"changed bytes").unwrap();
                fs::write(&path, b"public fixture").unwrap();
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(watch.check().is_err());
            assert!(watch.check().is_err(), "draining must not restore custody");
        }
    }

    #[test]
    fn directory_reads_and_child_attributes_are_not_entry_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("child");
        fs::write(&path, b"public fixture").unwrap();
        let directory = File::open(temp.path()).unwrap();
        let watch = CustodyWatch::directory(&directory).unwrap();
        fs::read(&path).unwrap();
        fs::read_dir(temp.path()).unwrap().for_each(drop);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        watch.check().unwrap();
        watch.check().unwrap();
    }

    #[test]
    fn directory_entry_rename_round_trip_is_sticky_without_clock_delays() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("delivered");
        let moved = temp.path().join("moved");
        fs::create_dir(&path).unwrap();
        let directory = File::open(temp.path()).unwrap();
        let watch = CustodyWatch::directory(&directory).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::rename(&moved, &path).unwrap();
        assert!(watch.check().is_err());
        assert!(watch.check().is_err());
    }

    #[test]
    fn watch_uses_the_pinned_inode_after_its_name_is_rebound() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proof");
        let moved = temp.path().join("old");
        fs::write(&path, b"public fixture").unwrap();
        let pinned = File::open(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"different inode").unwrap();
        let watch = CustodyWatch::file(&pinned).unwrap();
        fs::set_permissions(&moved, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(watch.check().is_err());
    }

    #[test]
    fn lost_or_incomplete_event_observation_is_refused() {
        let event = |wd: i32, mask: u32, length: u32| {
            [
                wd.to_ne_bytes(),
                mask.to_ne_bytes(),
                0u32.to_ne_bytes(),
                length.to_ne_bytes(),
            ]
            .concat()
        };
        for bytes in [
            event(-1, libc::IN_Q_OVERFLOW, 0),
            event(1, libc::IN_IGNORED, 0),
            event(1, libc::IN_UNMOUNT, 0),
            event(2, libc::IN_ATTRIB, 0),
            event(1, libc::IN_ATTRIB, u32::MAX),
            vec![0u8; HEADER - 1],
        ] {
            assert!(changed(&bytes, 1, Kind::Directory).is_err());
        }
    }
}
