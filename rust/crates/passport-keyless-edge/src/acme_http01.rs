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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
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

pub const SNAPSHOT_BASENAME: &str = "active.json";
pub const SNAPSHOT_SCHEMA: &str = "elevenid.acme-http01/v1";
pub const MAX_SNAPSHOT_BYTES: u64 = 4096;
pub const MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_CHALLENGES: usize = 2;
const MIN_TOKEN_LENGTH: usize = 22;
const MAX_TOKEN_LENGTH: usize = 256;
const PATH_PREFIX: &str = "/.well-known/acme-challenge/";
const INVALID_SNAPSHOT: &str = "HTTP-01 challenge snapshot unavailable or invalid";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub identifier: String,
    pub token: String,
    pub key_authorization: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub challenges: Vec<Challenge>,
}

impl Snapshot {
    /// Parse directly into deny-unknown-fields structs. Serde also rejects
    /// duplicate fields, rather than silently taking the last JSON value.
    pub fn parse(
        bytes: &[u8],
        allowed: &AllowedIdentifiers,
        now: u64,
    ) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(INVALID_SNAPSHOT);
        }
        let snapshot: Self = serde_json::from_slice(bytes).map_err(|_| INVALID_SNAPSHOT)?;
        if snapshot.schema != SNAPSHOT_SCHEMA
            || snapshot.created_at > now
            || snapshot.expires_at <= now
            || snapshot.expires_at <= snapshot.created_at
            || snapshot.expires_at - snapshot.created_at > MAX_LIFETIME_SECONDS
            || snapshot.challenges.len() > MAX_CHALLENGES
        {
            return Err(INVALID_SNAPSHOT);
        }
        let mut identifiers = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        for challenge in &snapshot.challenges {
            if !allowed
                .identifiers
                .iter()
                .any(|value| value.identifier == challenge.identifier)
                || !identifiers.insert(&challenge.identifier)
                || !tokens.insert(&challenge.token)
                || !valid_token(&challenge.token)
            {
                return Err(INVALID_SNAPSHOT);
            }
            let (token, thumbprint) = challenge
                .key_authorization
                .split_once('.')
                .ok_or(INVALID_SNAPSHOT)?;
            if token != challenge.token
                || thumbprint.len() != 43
                || URL_SAFE_NO_PAD
                    .decode(thumbprint)
                    .map_or(true, |bytes| bytes.len() != 32)
            {
                return Err(INVALID_SNAPSHOT);
            }
        }
        Ok(snapshot)
    }
}

fn valid_token(token: &str) -> bool {
    (MIN_TOKEN_LENGTH..=MAX_TOKEN_LENGTH).contains(&token.len())
        && token
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
}

#[derive(Clone, Debug)]
struct Identifier {
    identifier: String,
    authority: String,
}

#[derive(Clone, Debug)]
pub struct AllowedIdentifiers {
    identifiers: Vec<Identifier>,
}

impl AllowedIdentifiers {
    pub fn from_origins(canonical: &str, alias: Option<&str>) -> Result<Self, &'static str> {
        let canonical = PublicOrigin::parse(canonical).map_err(|_| "invalid HTTP-01 DNS origin")?;
        if canonical.dns_name().is_none()
            || canonical.is_loopback()
            || canonical.did_web_authority().is_err()
        {
            return Err("HTTP-01 requires a configured DNS identity");
        }
        let mut identifiers = vec![Identifier {
            identifier: canonical.host().into(),
            authority: canonical.host().into(),
        }];
        if let Some(alias) = alias.filter(|value| !value.is_empty()) {
            let alias = PublicOrigin::parse(alias).map_err(|_| "invalid HTTP-01 IP origin")?;
            let ip = alias.ip_address().ok_or("HTTP-01 alias must be an IP")?;
            if alias.is_loopback() {
                return Err("HTTP-01 alias must not be loopback");
            }
            identifiers.push(Identifier {
                identifier: ip.to_string(),
                authority: if ip.is_ipv6() {
                    format!("[{ip}]")
                } else {
                    ip.to_string()
                },
            });
        }
        Ok(Self { identifiers })
    }

    fn identifier_for_authority(&self, authority: &str) -> Option<&str> {
        self.identifiers
            .iter()
            .find(|value| {
                authority == value.authority
                    || authority.strip_suffix(":80") == Some(value.authority.as_str())
            })
            .map(|value| value.identifier.as_str())
    }

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
