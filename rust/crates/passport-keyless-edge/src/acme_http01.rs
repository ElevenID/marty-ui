//! Public HTTP-01 snapshot and responder contract.
//!
//! The owner atomically replaces `active.json` inside a stable directory mounted
//! read-only into this service. It contains ONLY public challenge data:
//!
//! ```json
//! {"schema":"elevenid.acme-http01/v1","created_at":1700000000,
//!  "expires_at":1700000300,"challenges":[
//!    {"identifier":"marty.example.com","token":"abcdefghijklmnopqrstuv",
//!     "key_authorization":"abcdefghijklmnopqrstuv.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}
//! ```
//!
//! `identifier` is a canonical DNS name or an unbracketed canonical IP literal,
//! without a port. A snapshot may hold zero, one or two challenges, each for a
//! distinct configured identifier and token. Its lifetime is at most 24 hours;
//! expired, future, missing and malformed snapshots serve no challenge. Clearing
//! the file or publishing an empty list withdraws all challenges. Writers must
//! create a complete temporary regular file, flush it, rename it to `active.json`
//! in the same directory, and flush the directory; in-place writes are unsupported.
//! The file must belong to the directory owner and neither may be group/world
//! writable. No account keys, API credentials, authorization URLs or certificates
//! belong in this projection. The ACME challenge token itself is public data.
//!
//! Configuration: `MARTY_ACME_HTTP01_BIND` is an unprivileged socket address;
//! `MARTY_ACME_HTTP01_CANONICAL_ORIGIN` is the configured HTTPS DNS origin;
//! optional `MARTY_ACME_HTTP01_PUBLIC_ENTRY_ORIGIN` is its HTTPS IP alias; and
//! `MARTY_ACME_HTTP01_DIRECTORY` is the absolute snapshot directory. Public
//! port-80 forwarding is a deployment responsibility. Only GET challenge URLs
//! are served; there are no application, health, administration or redirect APIs.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri},
    routing::any,
    Router,
};
use std::{
    ffi::CString,
    fs::{File, Metadata, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

use marty_selfhost_identity::acme_http01::valid_token;
pub use marty_selfhost_identity::acme_http01::{
    AllowedIdentifiers, Challenge, Snapshot, MAX_CHALLENGES, MAX_LIFETIME_SECONDS,
    MAX_SNAPSHOT_BYTES, SNAPSHOT_BASENAME, SNAPSHOT_SCHEMA,
};

const PATH_PREFIX: &str = "/.well-known/acme-challenge/";
const INVALID_SNAPSHOT: &str = "HTTP-01 challenge snapshot unavailable or invalid";

trait HttpChallengeRequest {
    fn request<'a>(
        &'a self,
        method: &Method,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Option<(&'a str, String)>;
}

impl HttpChallengeRequest for AllowedIdentifiers {
    fn request<'a>(
        &'a self,
        method: &Method,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Option<(&'a str, String)> {
        if *method != Method::GET
            || headers.get_all(header::HOST).iter().count() != 1
            || headers.contains_key(header::UPGRADE)
            || headers.contains_key(header::TRANSFER_ENCODING)
            || headers
                .get(header::CONTENT_LENGTH)
                .is_some_and(|value| value.as_bytes() != b"0")
            || uri.query().is_some()
            || uri.scheme_str().is_some_and(|scheme| scheme != "http")
        {
            return None;
        }
        let host = headers.get(header::HOST)?.to_str().ok()?;
        let identifier = self.identifier_for_authority(host)?;
        if uri.authority().is_some_and(|authority| {
            self.identifier_for_authority(authority.as_str()) != Some(identifier)
        }) {
            return None;
        }
        let token = uri.path().strip_prefix(PATH_PREFIX)?;
        valid_token(token).then(|| (identifier, token.to_owned()))
    }
}

pub fn validate_bind(value: &str) -> Result<SocketAddr, &'static str> {
    let bind: SocketAddr = value
        .parse()
        .map_err(|_| "invalid HTTP-01 listener address")?;
    if bind.port() < 1024
        || bind.ip().is_multicast()
        || bind.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        || matches!(bind.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
    {
        return Err("HTTP-01 requires an unprivileged unicast listener");
    }
    Ok(bind)
}

struct Directory {
    held: File,
    owner: u32,
}

fn child(parent: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File, &'static str> {
    let name = CString::new(name.as_bytes()).map_err(|_| INVALID_SNAPSHOT)?;
    // SAFETY: both arguments remain valid for openat; flags forbid following
    // a symlink and set close-on-exec. A successful descriptor is owned below.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(INVALID_SNAPSHOT);
    }
    // SAFETY: openat returned a fresh valid descriptor and ownership transfers
    // exactly once to File, including all subsequent error paths.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Directory {
    fn open(path: &Path) -> Result<Self, &'static str> {
        if !path.is_absolute() {
            return Err("HTTP-01 snapshot directory must be absolute");
        }
        let mut held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|_| INVALID_SNAPSHOT)?;
        // Walk from a held root directory: neither the leaf nor an ancestor
        // symlink can redirect the mount lookup between checking and opening.
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    held = child(&held, name, libc::O_RDONLY | libc::O_DIRECTORY)?
                }
                _ => return Err(INVALID_SNAPSHOT),
            }
        }
        let metadata = held.metadata().map_err(|_| INVALID_SNAPSHOT)?;
        if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
            return Err(INVALID_SNAPSHOT);
        }
        Ok(Self {
            held,
            owner: metadata.uid(),
        })
    }

    fn read(&self, allowed: &AllowedIdentifiers, now: u64) -> Result<Snapshot, &'static str> {
        let file = child(
            &self.held,
            std::ffi::OsStr::new(SNAPSHOT_BASENAME),
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        let before = file.metadata().map_err(|_| INVALID_SNAPSHOT)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != self.owner
            || before.mode() & 0o022 != 0
            || !(1..=MAX_SNAPSHOT_BYTES).contains(&before.len())
        {
            return Err(INVALID_SNAPSHOT);
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&file)
            .take(MAX_SNAPSHOT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| INVALID_SNAPSHOT)?;
        let after = file.metadata().map_err(|_| INVALID_SNAPSHOT)?;
        if bytes.len() as u64 != before.len() || !unchanged(&before, &after) {
            return Err(INVALID_SNAPSHOT);
        }
        Snapshot::parse(&bytes, allowed, now)
    }
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[derive(Clone)]
pub struct Responder {
    directory: Arc<Directory>,
    allowed: AllowedIdentifiers,
    reads: Arc<Semaphore>,
}

impl Responder {
    /// Opening an empty projection is valid: issuance may publish its first
    /// challenge only after the independently managed listener has started.
    pub fn open(path: &Path, allowed: AllowedIdentifiers) -> Result<Self, &'static str> {
        Ok(Self {
            directory: Arc::new(Directory::open(path)?),
            allowed,
            reads: Arc::new(Semaphore::new(16)),
        })
    }

    pub fn router(self) -> Router {
        Router::new().fallback(any(handle)).with_state(self)
    }
}

fn response(status: StatusCode, value: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(value))
        .expect("static HTTP-01 response")
}

async fn handle(State(state): State<Responder>, request: Request<Body>) -> Response<Body> {
    let Some((identifier, token)) =
        state
            .allowed
            .request(request.method(), request.headers(), request.uri())
    else {
        return response(StatusCode::NOT_FOUND, String::new());
    };
    let identifier = identifier.to_owned();
    let Ok(permit) = state.reads.clone().try_acquire_owned() else {
        return response(StatusCode::SERVICE_UNAVAILABLE, String::new());
    };
    // Bound concurrent filesystem work and never let a nonregular snapshot
    // (especially a FIFO) block the listener or consume an unbounded work queue.
    let answer = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let snapshot = state.directory.read(&state.allowed, now).ok()?;
        snapshot
            .challenges
            .into_iter()
            .find(|challenge| challenge.identifier == identifier && challenge.token == token)
            .map(|challenge| challenge.key_authorization)
    })
    .await
    .ok()
    .flatten();
    match answer {
        Some(value) => response(StatusCode::OK, value),
        None => response(StatusCode::NOT_FOUND, String::new()),
    }
}

#[cfg(test)]
#[path = "acme_http01_tests.rs"]
mod tests;
