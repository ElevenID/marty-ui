//! Controller-view observation of a connected census peer. This is not proof
//! of container membership, installation ownership, or deletion authority.
//! The future controller must independently bind the peer to its exact owned
//! Engine/container/image/command/binds and preserve stopped-writer custody.
//! No Docker, namespace entry, file-content census, or installation mutation.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until the distinct native census protocol is integrated.

use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
};

#[derive(Debug)]
pub(crate) struct Incomplete;
type Result<T> = std::result::Result<T, Incomplete>;
fn require(value: bool) -> Result<()> {
    value.then_some(()).ok_or(Incomplete)
}

#[derive(Clone, PartialEq, Eq)]
struct Interval {
    inside: u32,
    outside: u32,
    count: u32,
}

/// Raw kernel bytes are retained so two differently expressed projections
/// cannot silently compare equal. Values must be read in the controller view.
#[derive(Clone, PartialEq, Eq)]
struct IdMap {
    raw: Vec<u8>,
    intervals: Vec<Interval>,
}
impl IdMap {
    fn parse(raw: Vec<u8>) -> Result<Self> {
        require(!raw.is_empty() && raw.len() <= 4096)?;
        let text = std::str::from_utf8(&raw).map_err(|_| Incomplete)?;
        let mut intervals: Vec<Interval> = Vec::new();
        for line in text.lines() {
            require(intervals.len() < 32)?;
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            require(fields.len() == 3)?;
            let parse = |value: &str| -> Result<u32> {
                require(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))?;
                value.parse().map_err(|_| Incomplete)
            };
            let item = Interval {
                inside: parse(fields[0])?,
                outside: parse(fields[1])?,
                count: parse(fields[2])?,
            };
            let end = |start: u32, count: u32| u64::from(start) + u64::from(count);
            // UINT32_MAX is the reserved unmapped ID, never an owner.
            require(
                item.count > 0
                    && end(item.inside, item.count) <= u64::from(u32::MAX)
                    && end(item.outside, item.count) <= u64::from(u32::MAX),
            )?;
            for prior in &intervals {
                let separate = |a: u32, ac: u32, b: u32, bc: u32| {
                    end(a, ac) <= u64::from(b) || end(b, bc) <= u64::from(a)
                };
                require(
                    separate(item.inside, item.count, prior.inside, prior.count)
                        && separate(item.outside, item.count, prior.outside, prior.count),
                )?;
            }
            intervals.push(item);
        }
        require(!intervals.is_empty())?;
        Ok(Self { raw, intervals })
    }
    fn owner(&self, value: u32, overflow: u32) -> Result<u32> {
        // An unmapped owner can look like a genuinely mapped overflow ID.
        // Refuse either interpretation instead of silently adopting it.
        require(value != overflow && value != u32::MAX)?;
        let projected = self
            .intervals
            .iter()
            .find_map(|item| {
                let offset = value.checked_sub(item.inside)?;
                (offset < item.count).then(|| item.outside + offset)
            })
            .ok_or(Incomplete)?;
        require(projected != overflow && projected != u32::MAX)?;
        Ok(projected)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Namespace {
    dev: u64,
    ino: u64,
}
fn namespace(file: &File) -> Result<Namespace> {
    let metadata = file.metadata().map_err(|_| Incomplete)?;
    require(metadata.dev() != 0 && metadata.ino() != 0)?;
    Ok(Namespace {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}
fn open_at(parent: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name).map_err(|_| Incomplete)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(Incomplete)
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn bounded(file: File, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Incomplete)?;
    require(!bytes.is_empty() && bytes.len() <= maximum)?;
    Ok(bytes)
}
fn procfs() -> Result<File> {
    let file = File::open("/proc").map_err(|_| Incomplete)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } == 0 && info.f_type as i64 == 0x9fa0,
    )?;
    Ok(file)
}
fn read_at(parent: &File, name: &str, maximum: usize) -> Result<Vec<u8>> {
    bounded(
        open_at(parent, name, libc::O_RDONLY | libc::O_NOFOLLOW)?,
        maximum,
    )
}
fn start_time(bytes: &[u8], pid: libc::pid_t) -> Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| Incomplete)?;
    require(text.starts_with(&format!("{pid} (")))?;
    let (_, fields) = text.rsplit_once(") ").ok_or(Incomplete)?;
    // Fields after comm begin at field3; starttime is field22.
    let value = fields.split_ascii_whitespace().nth(19).ok_or(Incomplete)?;
    require(value.bytes().all(|b| b.is_ascii_digit()))?;
    let value = value.parse().map_err(|_| Incomplete)?;
    require(value > 0)?;
    Ok(value)
}
fn overflow(proc: &File, name: &str) -> Result<(Vec<u8>, u32)> {
    let bytes = read_at(proc, name, 32)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Incomplete)?
        .trim_ascii();
    require(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))?;
    let value = text.parse().map_err(|_| Incomplete)?;
    require(value != u32::MAX)?;
    Ok((bytes, value))
}

/// Kernel-pinned peer process plus held proc/user/PID namespace descriptors.
/// No pathname/PID supplied by the helper or Docker is accepted as identity.
pub(crate) struct ConnectedPeer {
    pidfd: File,
    proc: File,
    process: File,
    user_namespace: File,
    pid_namespace: File,
    controller_namespace: File,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProjectionObservation {
    pid: libc::pid_t,
    peer_uid: u32,
    peer_gid: u32,
    start_time: u64,
    user_namespace: Namespace,
    pid_namespace: Namespace,
    controller_namespace: Namespace,
    uid_map: IdMap,
    gid_map: IdMap,
    overflow_uid: (Vec<u8>, u32),
    overflow_gid: (Vec<u8>, u32),
    cgroup: Vec<u8>,
}
/// Private, borrowed metadata for the independent Engine/container binder.
/// Connect-time credentials and a namespace/cgroup match are not authorization.
pub(crate) struct PeerBindingEvidence<'a> {
    pub pid: libc::pid_t,
    pub connect_uid: u32,
    pub connect_gid: u32,
    pub start_time: u64,
    pub user_namespace: (u64, u64),
    pub pid_namespace: (u64, u64),
    pub controller_namespace: (u64, u64),
    pub uid_map: &'a [u8],
    pub gid_map: &'a [u8],
    pub overflow_uid: &'a [u8],
    pub overflow_gid: &'a [u8],
    pub cgroup: &'a [u8],
}
impl ProjectionObservation {
    pub(crate) fn binding_evidence(&self) -> PeerBindingEvidence<'_> {
        PeerBindingEvidence {
            pid: self.pid,
            connect_uid: self.peer_uid,
            connect_gid: self.peer_gid,
            start_time: self.start_time,
            user_namespace: (self.user_namespace.dev, self.user_namespace.ino),
            pid_namespace: (self.pid_namespace.dev, self.pid_namespace.ino),
            controller_namespace: (self.controller_namespace.dev, self.controller_namespace.ino),
            uid_map: &self.uid_map.raw,
            gid_map: &self.gid_map.raw,
            overflow_uid: &self.overflow_uid.0,
            overflow_gid: &self.overflow_gid.0,
            cgroup: &self.cgroup,
        }
    }
    /// Not authorization: these IDs are only metadata in the controller view.
    /// Same-namespace uid_map files describe the parent instead, so refuse.
    fn owner_in_controller(&self, uid: u32, gid: u32) -> Result<(u32, u32)> {
        require(self.user_namespace != self.controller_namespace)?;
        Ok((
            self.uid_map.owner(uid, self.overflow_uid.1)?,
            self.gid_map.owner(gid, self.overflow_gid.1)?,
        ))
    }
}
impl ConnectedPeer {
    pub(crate) fn pin(stream: &UnixStream) -> Result<Self> {
        // SO_PEERPIDFD obtains the socket peer's pidfd atomically. Numeric-PID
        // fallback would leave a reuse race and is deliberately unsupported.
        let mut raw = -1;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERPIDFD,
                    (&mut raw as *mut libc::c_int).cast(),
                    &mut length,
                )
            } == 0
                && raw >= 0,
        )?;
        let pidfd = unsafe { File::from_raw_fd(raw) };
        require(length as usize == std::mem::size_of::<libc::c_int>())?;
        require(unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0)?;
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast(),
                    &mut length,
                )
            } == 0
                && length as usize == std::mem::size_of::<libc::ucred>()
                && credentials.pid > 0,
        )?;
        let proc = procfs()?;
        let process = open_at(
            &proc,
            &credentials.pid.to_string(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        // These fixed procfs magic links intentionally open namespace handles.
        let user_namespace = open_at(&process, "ns/user", libc::O_RDONLY)?;
        let pid_namespace = open_at(&process, "ns/pid", libc::O_RDONLY)?;
        let controller_namespace = open_at(&proc, "thread-self/ns/user", libc::O_RDONLY)?;
        let peer = Self {
            pidfd,
            proc,
            process,
            user_namespace,
            pid_namespace,
            controller_namespace,
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
        };
        peer.alive()?;
        peer.observe()?;
        Ok(peer)
    }
    fn alive(&self) -> Result<()> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(unsafe { libc::poll(&mut descriptor, 1, 0) } == 0 && descriptor.revents == 0)
    }
    pub(crate) fn observe(&self) -> Result<ProjectionObservation> {
        self.alive()?;
        let before = start_time(&read_at(&self.process, "stat", 4096)?, self.pid)?;
        let user_namespace = namespace(&self.user_namespace)?;
        let pid_namespace = namespace(&self.pid_namespace)?;
        let controller_namespace = namespace(&self.controller_namespace)?;
        require(
            namespace(&open_at(&self.process, "ns/user", libc::O_RDONLY)?)? == user_namespace
                && namespace(&open_at(&self.process, "ns/pid", libc::O_RDONLY)?)? == pid_namespace
                && namespace(&open_at(&self.proc, "thread-self/ns/user", libc::O_RDONLY)?)?
                    == controller_namespace,
        )?;
        let value = ProjectionObservation {
            pid: self.pid,
            peer_uid: self.uid,
            peer_gid: self.gid,
            start_time: before,
            user_namespace,
            pid_namespace,
            controller_namespace,
            uid_map: IdMap::parse(read_at(&self.process, "uid_map", 4096)?)?,
            gid_map: IdMap::parse(read_at(&self.process, "gid_map", 4096)?)?,
            overflow_uid: overflow(&self.proc, "sys/kernel/overflowuid")?,
            overflow_gid: overflow(&self.proc, "sys/kernel/overflowgid")?,
            cgroup: read_at(&self.process, "cgroup", 16384)?,
        };
        require(
            self.uid != value.overflow_uid.1
                && self.gid != value.overflow_gid.1
                && self.uid != u32::MAX
                && self.gid != u32::MAX,
        )?;
        require(
            start_time(&read_at(&self.process, "stat", 4096)?, self.pid)? == before
                && namespace(&open_at(&self.process, "ns/user", libc::O_RDONLY)?)?
                    == value.user_namespace
                && namespace(&open_at(&self.process, "ns/pid", libc::O_RDONLY)?)?
                    == value.pid_namespace
                && namespace(&open_at(&self.proc, "thread-self/ns/user", libc::O_RDONLY)?)?
                    == value.controller_namespace,
        )?;
        self.alive()?;
        Ok(value)
    }
    pub(crate) fn require_unchanged(&self, expected: &ProjectionObservation) -> Result<()> {
        require(self.observe()? == *expected)
    }
    /// Normalize one bounded census owner set between fresh matching snapshots.
    /// The operator assertion must come from the independent receipt/Engine
    /// owner. This function does not authenticate that assertion or the census.
    pub(crate) fn project_rootless_owners(
        &self,
        expected: &ProjectionObservation,
        operator: (u32, u32),
        owners: &[(u32, u32)],
    ) -> Result<Vec<(u32, u32)>> {
        require(operator.0 != 0 && !owners.is_empty() && owners.len() <= 4097)?;
        self.require_unchanged(expected)?;
        require(
            (expected.peer_uid, expected.peer_gid) == operator
                && expected.owner_in_controller(0, 0)? == operator,
        )?;
        let result = owners
            .iter()
            .map(|&(uid, gid)| expected.owner_in_controller(uid, gid))
            .collect::<Result<Vec<_>>>()?;
        self.require_unchanged(expected)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn rootless_map_projects_every_owner_and_refuses_overflow_ambiguity() {
        let map = IdMap::parse(
            b"         0       1001          1\n         1     100000      65536\n".to_vec(),
        )
        .unwrap();
        assert_eq!(map.owner(0, 65534).unwrap(), 1001);
        assert_eq!(map.owner(100, 65534).unwrap(), 100099);
        assert!(map.owner(65534, 65534).is_err());
        assert!(map.owner(65537, 65534).is_err());
        assert!(map.owner(u32::MAX, 65534).is_err());
        assert!(IdMap::parse(b"0 65534 1\n".to_vec())
            .unwrap()
            .owner(0, 65534)
            .is_err());
    }
    #[test]
    fn malformed_overlapping_reserved_or_unbounded_maps_are_refused() {
        for input in [
            "",
            "0 1000 0\n",
            "0 1000 2\n1 2000 2\n",
            "0 1000 2\n2 1001 2\n",
            "0 4294967294 2\n",
            "4294967295 1 1\n",
            "0 -1 1\n",
            "0 1 1 extra\n",
            "0 1 1\n\n",
        ] {
            assert!(IdMap::parse(input.as_bytes().to_vec()).is_err());
        }
        assert!(IdMap::parse(vec![b'0'; 4097]).is_err());
        assert!(IdMap::parse(
            (0..33)
                .map(|i| format!("{i} {} 1\n", i + 1000))
                .collect::<String>()
                .into_bytes()
        )
        .is_err());
    }
    #[test]
    fn actual_peer_pidfd_preserves_kernel_identity_without_same_namespace_projection() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let peer = ConnectedPeer::pin(&socket).unwrap();
        assert_eq!(peer.pid, unsafe { libc::getpid() });
        let observation = peer.observe().unwrap();
        peer.require_unchanged(&observation).unwrap();
        assert!(observation
            .owner_in_controller(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
            .is_err());
        let mut substituted = observation.clone();
        substituted.start_time += 1;
        assert!(peer.require_unchanged(&substituted).is_err());
    }
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    fn connected_child(depth: usize) -> (tempfile::TempDir, OwnedChild, UnixStream) {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temporary.path().join("controller.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut command = Command::new(if depth == 0 { "python3" } else { "unshare" });
        for level in 0..depth {
            if level != 0 {
                command.arg("unshare");
            }
            command.args(["--user", "--map-root-user"]);
        }
        if depth != 0 {
            command.arg("python3");
        }
        let child = OwnedChild(command.args(["-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); s.sendall(b'x'); s.recv(1)",
            path.to_str().unwrap()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5))
                }
                Err(_) => panic!("owned peer did not connect"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut ready = [0];
        stream.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [b'x']);
        (temporary, child, stream)
    }
    #[test]
    fn actual_private_socket_peer_exit_invalidates_held_projection() {
        let (_temporary, mut child, mut stream) = connected_child(0);
        let peer = ConnectedPeer::pin(&stream).unwrap();
        assert_eq!(peer.pid as u32, child.0.id());
        let before = peer.observe().unwrap();
        peer.require_unchanged(&before).unwrap();
        stream.write_all(b"x").unwrap();
        assert!(child.0.wait().unwrap().success());
        assert!(peer.observe().is_err());
        assert!(peer.require_unchanged(&before).is_err());
    }
    #[test]
    #[ignore = "explicit owned single/nested user-namespace kernel qualification; unshare admission required"]
    fn actual_single_and_nested_namespace_controller_projection() {
        let operator = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        assert_ne!(operator.0, 0, "use an ordinary nonroot controller");
        for depth in [1, 2] {
            let (_temporary, mut child, mut stream) = connected_child(depth);
            let peer = ConnectedPeer::pin(&stream).unwrap();
            let snapshot = peer.observe().unwrap();
            assert_eq!(snapshot.binding_evidence().pid as u32, child.0.id());
            assert_eq!(
                peer.project_rootless_owners(&snapshot, operator, &[(0, 0)])
                    .unwrap(),
                [operator]
            );
            assert!(peer
                .project_rootless_owners(&snapshot, operator, &[(1, 0)])
                .is_err());
            assert!(peer
                .project_rootless_owners(&snapshot, (operator.0 + 1, operator.1), &[(0, 0)])
                .is_err());
            assert!(peer
                .project_rootless_owners(&snapshot, operator, &[(65534, 0)])
                .is_err());
            stream.write_all(b"x").unwrap();
            assert!(child.0.wait().unwrap().success());
            assert!(peer
                .project_rootless_owners(&snapshot, operator, &[(0, 0)])
                .is_err());
        }
    }
}
