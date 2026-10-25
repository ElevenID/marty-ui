//! Public GitHub release downloads. No payload execution or signature admission.
//! A receipt proves observed bytes (and optionally an expected digest), never
//! release eligibility. The caller authenticates records and signature sidecars.
//! Failed/cancelled downloads preserve exclusively created private partial files.
#![cfg(target_os = "linux")]

use reqwest::{redirect::Policy, Client, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
    time::Duration,
};

pub type Result<T> = std::result::Result<T, String>;
const REPOSITORY: &str = "ElevenID/marty-ui";
const RECORD_LIMIT: u64 = 65536;
const SIDECAR_LIMIT: u64 = 1024 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Serialize)]
pub struct DownloadReceipt {
    pub asset: String,
    pub bytes: u64,
    pub sha256: String,
    /// True only when compared with the caller's expected digest AND size.
    /// It does not mean that the caller's expectation was authenticated here.
    pub hash_verified: bool,
}

fn artifact_limit(asset: &str) -> Option<u64> {
    match asset {
        "install.sh" => Some(65536),
        "marty-deploy-linux-amd64" => Some(512 * 1024 * 1024),
        "prepared-selfhost-bundle.zip" => Some(256 * 1024 * 1024),
        "prepared-selfhost-images.json" => Some(65536),
        _ => None,
    }
}
fn record(asset: &str) -> bool {
    matches!(
        asset,
        "installer-inventory.json" | "installer-admission.json" | "installer-channel.json"
    )
}
fn base_asset(asset: &str) -> &str {
    asset
        .strip_suffix(".sigstore.json")
        .or_else(|| asset.strip_suffix(".provenance.jsonl"))
        .unwrap_or(asset)
}
fn valid_tag(tag: &str) -> bool {
    let pattern = regex::Regex::new(r"\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-nightly\.(20[0-9]{6})\.([1-9][0-9]*))?\z").unwrap();
    if tag.len() > 160 {
        return false;
    }
    let Some(capture) = pattern.captures(tag) else {
        return false;
    };
    capture
        .get(4)
        .is_none_or(|date| chrono::NaiveDate::parse_from_str(date.as_str(), "%Y%m%d").is_ok())
}
fn asset_url(tag: &str, asset: &str) -> Result<Url> {
    let base = base_asset(asset);
    if !(artifact_limit(base).is_some() || record(base)) {
        return Err("unsupported installer release asset".into());
    }
    let channel = matches!(
        tag,
        "installer-channel-nightly" | "installer-channel-stable"
    );
    if (channel && base != "installer-channel.json")
        || (!channel && (!valid_tag(tag) || base == "installer-channel.json"))
    {
        return Err("invalid installer release tag or channel asset".into());
    }
    Url::parse(&format!(
        "https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}"
    ))
    .map_err(|_| "invalid release download URL".into())
}
fn allowed_delivery(url: &Url) -> bool {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return false;
    }
    match url.host_str() {
        Some("github.com") => url
            .path()
            .starts_with("/ElevenID/marty-ui/releases/download/"),
        Some(
            "release-assets.githubusercontent.com"
            | "objects.githubusercontent.com"
            | "github-releases.githubusercontent.com",
        ) => true,
        _ => false,
    }
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct PartialOutput {
    file: File,
    parent: File,
}
impl PartialOutput {
    fn create(destination: &Path) -> Result<Self> {
        if !destination.is_absolute() {
            return Err("download destination must be absolute".into());
        }
        let mut components = destination.components();
        if components.next() != Some(Component::RootDir) {
            return Err("invalid download destination".into());
        }
        let mut names = Vec::new();
        for component in components {
            match component {
                Component::Normal(n) => names
                    .push(CString::new(n.as_bytes()).map_err(|_| "invalid download destination")?),
                _ => return Err("download destination must not contain traversal".into()),
            }
        }
        let leaf = names.pop().ok_or("download destination has no filename")?;
        let mut parent = File::open("/").map_err(|_| "download parent unavailable")?;
        let uid = unsafe { libc::geteuid() };
        for name in names {
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("download ancestor is unavailable or linked".into());
            }
            parent = unsafe { File::from_raw_fd(fd) };
            let metadata = parent
                .metadata()
                .map_err(|_| "download ancestor unavailable")?;
            if (metadata.uid() != 0 && metadata.uid() != uid)
                || (metadata.mode() & 0o022 != 0
                    && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
            {
                return Err("download ancestor is not trusted".into());
            }
        }
        let metadata = parent
            .metadata()
            .map_err(|_| "download parent unavailable")?;
        if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err("download parent must be an owned private directory".into());
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("download output exists or cannot be created".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err("download output cannot be protected".into());
        }
        parent
            .sync_all()
            .map_err(|_| "cannot persist download output creation")?;
        Ok(Self { file, parent })
    }
}
impl Drop for PartialOutput {
    fn drop(&mut self) {
        // Best effort durability on every early return/cancellation. Never unlink
        // partially downloaded bytes: the caller must inspect/dispose them.
        let _ = self.file.sync_all();
        let _ = self.parent.sync_all();
    }
}
struct Transfer {
    bytes: u64,
    limit: u64,
    hasher: Sha256,
}
impl Transfer {
    fn new(limit: u64) -> Self {
        Self {
            bytes: 0,
            limit,
            hasher: Sha256::new(),
        }
    }
    fn append(&mut self, output: &mut impl Write, chunk: &[u8]) -> Result<()> {
        let size = self
            .bytes
            .checked_add(chunk.len() as u64)
            .ok_or("download size overflow")?;
        if size > self.limit {
            return Err("download exceeds size limit".into());
        }
        output
            .write_all(chunk)
            .map_err(|_| "cannot write private download output")?;
        self.hasher.update(chunk);
        self.bytes = size;
        Ok(())
    }
    fn finish(self, asset: &str, expected: Option<(u64, &str)>) -> Result<DownloadReceipt> {
        let digest = format!("{:x}", self.hasher.finalize());
        if self.bytes == 0 {
            return Err("download is empty".into());
        }
        if let Some((size, hash)) = expected {
            if self.bytes != size || digest != hash {
                return Err("download differs from expected size or digest".into());
            }
        }
        Ok(DownloadReceipt {
            asset: asset.into(),
            bytes: self.bytes,
            sha256: digest,
            hash_verified: expected.is_some(),
        })
    }
}

pub struct GitHubReleaseFetcher {
    client: Client,
}
impl GitHubReleaseFetcher {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(20))
            .timeout(TOTAL_TIMEOUT)
            .user_agent("marty-installer/1")
            .redirect(Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || !allowed_delivery(attempt.url()) {
                    attempt.error("installer release redirect refused")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|_| "cannot initialize public HTTPS downloader")?;
        Ok(Self { client })
    }
    pub async fn fetch_verified(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
        expected_size: u64,
        expected_sha: &str,
    ) -> Result<DownloadReceipt> {
        let limit = artifact_limit(asset).ok_or("unsupported verified installer artifact")?;
        if expected_size == 0 || expected_size > limit || !sha(expected_sha) {
            return Err("invalid expected installer artifact size or digest".into());
        }
        self.download(
            tag,
            asset,
            destination,
            expected_size,
            Some((expected_size, expected_sha)),
        )
        .await
    }
    /// Fetches bounded metadata only. The caller must verify its signatures
    /// before interpreting it as an admitted release, inventory or channel.
    pub async fn fetch_record(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
    ) -> Result<DownloadReceipt> {
        if !record(asset) {
            return Err("unsupported installer record".into());
        }
        self.download(tag, asset, destination, RECORD_LIMIT, None)
            .await
    }
    /// Sidecars contain untrusted signature/provenance material until verified.
    pub async fn fetch_sidecar(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
    ) -> Result<DownloadReceipt> {
        if base_asset(asset) == asset {
            return Err("signature sidecar suffix required".into());
        }
        self.download(tag, asset, destination, SIDECAR_LIMIT, None)
            .await
    }
    async fn download(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
        limit: u64,
        expected: Option<(u64, &str)>,
    ) -> Result<DownloadReceipt> {
        let url = asset_url(tag, asset)?;
        let mut output = PartialOutput::create(destination)?;
        // Outer deadline includes response consumption, not just connection.
        tokio::time::timeout(TOTAL_TIMEOUT, async {
            let mut response = self
                .client
                .get(url)
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|_| "public GitHub download failed")?;
            if response.status() != reqwest::StatusCode::OK || !allowed_delivery(response.url()) {
                return Err("public GitHub asset unavailable or redirect refused".into());
            }
            if response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_some_and(|v| v.as_bytes() != b"identity")
            {
                return Err("encoded installer response refused".into());
            }
            if let Some(length) = response.content_length() {
                if length == 0 || length > limit || expected.is_some_and(|(size, _)| size != length)
                {
                    return Err("download content length differs or exceeds limit".into());
                }
            }
            let mut transfer = Transfer::new(limit);
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "public GitHub download interrupted")?
            {
                transfer.append(&mut output.file, &chunk)?;
            }
            let receipt = transfer.finish(asset, expected)?;
            output
                .file
                .sync_all()
                .map_err(|_| "cannot persist installer download")?;
            output
                .parent
                .sync_all()
                .map_err(|_| "cannot persist installer download directory")?;
            Ok(receipt)
        })
        .await
        .map_err(|_| "public GitHub download timed out".to_owned())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn private_temp() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn permits_only_fixed_repository_release_assets_and_valid_tags() {
        assert_eq!(
            asset_url("v1.2.3", "install.sh").unwrap().as_str(),
            "https://github.com/ElevenID/marty-ui/releases/download/v1.2.3/install.sh"
        );
        assert!(asset_url(
            "v1.2.3-nightly.20261025.42",
            "prepared-selfhost-bundle.zip.provenance.jsonl"
        )
        .is_ok());
        assert!(asset_url(
            "installer-channel-stable",
            "installer-channel.json.sigstore.json"
        )
        .is_ok());
        for (tag, asset) in [
            ("../../other", "install.sh"),
            ("v1.2.3", "../install.sh"),
            ("v01.2.3", "install.sh"),
            ("v1.2.3-nightly.20260230.42", "install.sh"),
            ("installer-channel-nightly", "marty-deploy-linux-amd64"),
            ("v1.2.3", "installer-channel.json"),
            ("v1.2.3", "install.sh.sigstore.json.sigstore.json"),
        ] {
            assert!(asset_url(tag, asset).is_err());
        }
    }
    #[test]
    fn redirects_reject_other_hosts_ports_auth_and_http() {
        for accepted in [
            "https://github.com/ElevenID/marty-ui/releases/download/v1.2.3/install.sh",
            "https://release-assets.githubusercontent.com/asset?signature=opaque",
            "https://objects.githubusercontent.com/asset",
        ] {
            assert!(allowed_delivery(&Url::parse(accepted).unwrap()));
        }
        for refused in [
            "http://release-assets.githubusercontent.com/asset",
            "https://evil.example/asset",
            "https://release-assets.githubusercontent.com.evil.example/asset",
            "https://user:password@github.com/ElevenID/marty-ui/releases/download/x/y",
            "https://github.com:8443/ElevenID/marty-ui/releases/download/x/y",
            "https://github.com/other/repository/releases/download/x/y",
            "https://github.com/login",
            "https://objects.githubusercontent.com/asset#fragment",
        ] {
            assert!(!allowed_delivery(&Url::parse(refused).unwrap()));
        }
    }
    #[test]
    fn exact_size_hash_and_stream_bound_are_enforced() {
        let mut bytes = Vec::new();
        let mut transfer = Transfer::new(4);
        transfer.append(&mut bytes, b"ab").unwrap();
        assert!(transfer.append(&mut bytes, b"cde").is_err());
        assert_eq!(bytes, b"ab");
        transfer.append(&mut bytes, b"cd").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"abcd"));
        assert!(
            transfer
                .finish("install.sh", Some((4, &hash)))
                .unwrap()
                .hash_verified
        );
        for (expected, digest) in [(5, hash.as_str()), (4, "wrong")] {
            let mut transfer = Transfer::new(4);
            transfer.append(&mut Vec::new(), b"abcd").unwrap();
            assert!(transfer
                .finish("install.sh", Some((expected, digest)))
                .is_err());
        }
        assert!(Transfer::new(4).finish("install.sh", None).is_err());
    }
    #[test]
    fn output_is_private_exclusive_and_partial_data_survives_errors() {
        let temp = private_temp();
        let path = temp.path().join("artifact");
        {
            let mut output = PartialOutput::create(&path).unwrap();
            let mut transfer = Transfer::new(2);
            transfer.append(&mut output.file, b"ab").unwrap();
            assert!(transfer.append(&mut output.file, b"c").is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"ab");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(PartialOutput::create(&path).is_err());
        let alias = temp.path().join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(PartialOutput::create(&alias.join("other")).is_err());
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PartialOutput::create(&temp.path().join("other")).is_err());
    }
    #[tokio::test]
    async fn invalid_request_is_refused_without_creating_output_or_network() {
        let temp = private_temp();
        let path = temp.path().join("artifact");
        let fetcher = GitHubReleaseFetcher::new().unwrap();
        assert!(fetcher
            .fetch_verified("v1.2.3", "install.sh", &path, 65537, &"a".repeat(64))
            .await
            .is_err());
        assert!(fetcher
            .fetch_record(
                "installer-channel-stable",
                "installer-admission.json",
                &path
            )
            .await
            .is_err());
        assert!(fetcher
            .fetch_sidecar("v1.2.3", "install.sh", &path)
            .await
            .is_err());
        assert!(!path.exists());
    }
}
