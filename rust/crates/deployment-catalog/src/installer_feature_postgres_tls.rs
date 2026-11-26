//! Local PostgreSQL transport custody for the fresh rootless feature profile.
//! Unlike application identities, PostgreSQL's native TLS listener requires a
//! file-backed key. This narrowly scoped infrastructure owner never exports its
//! CA key or makes either private key available to an application workload.
#![cfg(target_os = "linux")]

use crate::{
    installer_filesystem::DeviceBinding,
    installer_host_fs as fs,
    installer_state::{
        InstallerState, Journal, LockedInspection, LockedMaintenance, Phase, RuntimeProfile,
    },
};
use chrono::Datelike;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "managed feature PostgreSQL TLS custody or renewal is invalid; preserve its owner and evidence";
pub(crate) const RECORD: &str = "feature-postgres-transport.json";
pub(crate) const DIRECTORY: &str = "feature-postgres-transport";
pub(crate) const ENVIRONMENT: &str = "FEATURE_POSTGRES_TLS_DIR";
pub(crate) const SERVER_MOUNT: &str = "/run/postgres-transport";
pub(crate) const CA_CREDENTIAL: &str = "feature_postgres_ca";
const SCHEMA: &str = "elevenid.installer-feature-postgres-tls/v1";
const LEAF_DAYS: u64 = 90;
const RENEW_BEFORE: u64 = 30 * 86400;

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| REFUSED.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: DeviceBinding,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl DirectoryIdentity {
    fn observe(file: &File, mode: u32) -> Result<Self> {
        let meta = file.metadata().map_err(|_| REFUSED)?;
        require(
            meta.is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.gid() == unsafe { libc::getegid() }
                && meta.mode() & 0o7777 == mode,
        )?;
        Ok(Self {
            device: DeviceBinding::observe(file, REFUSED)?,
            inode: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        })
    }
    fn retained_matches(&self, mut observed: Self) -> bool {
        if !self.device.matches(observed.device) {
            return false;
        }
        observed.device = self.device;
        observed == *self
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    feature_profile_sha256: String,
    owner: DirectoryIdentity,
    server_projection: DirectoryIdentity,
    ca_sha256: String,
    ca_spki_sha256: String,
    server_spki_sha256: String,
    ca_not_before: u64,
    ca_not_after: u64,
    server_certificate_pem: String,
    server_certificate_sha256: String,
}

struct Owner {
    path: PathBuf,
    directory: File,
    server: File,
    directory_now: DirectoryIdentity,
    server_now: DirectoryIdentity,
    receipt: Receipt,
    ca_pem: Vec<u8>,
    ca_key: KeyPair,
    server_key: KeyPair,
    leaf_pem: Vec<u8>,
    leaf_not_after: u64,
    sequence: u32,
}

fn date(epoch: u64) -> Result<chrono::NaiveDate> {
    let seconds = i64::try_from(epoch).map_err(|_| REFUSED)?;
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|v| v.date_naive())
        .ok_or_else(|| REFUSED.into())
}
fn validity(params: &mut CertificateParams, before: u64, after: u64) -> Result<()> {
    let first = date(before)?;
    let last = date(after)?;
    require(before < after && before.is_multiple_of(86400) && after.is_multiple_of(86400))?;
    params.not_before = rcgen::date_time_ymd(first.year(), first.month() as u8, first.day() as u8);
    params.not_after = rcgen::date_time_ymd(last.year(), last.month() as u8, last.day() as u8);
    Ok(())
}
fn ca_params(id: uuid::Uuid, before: u64, after: u64) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| REFUSED)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ElevenID managed PostgreSQL {id}"),
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut params, before, after)?;
    Ok(params)
}
fn leaf_pem(key: &KeyPair, issuer: &Issuer<'_, &KeyPair>, observed: u64) -> Result<Vec<u8>> {
    let day = observed / 86400 * 86400;
    let mut params = CertificateParams::new(vec!["postgres".to_owned()]).map_err(|_| REFUSED)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "postgres");
    params.serial_number = Some(uuid::Uuid::new_v4().as_bytes().to_vec().into());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(
        &mut params,
        day.checked_sub(86400).ok_or(REFUSED)?,
        day + LEAF_DAYS * 86400,
    )?;
    Ok(params
        .signed_by(key, issuer)
        .map_err(|_| REFUSED)?
        .pem()
        .into_bytes())
}

fn create_file(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    require(!bytes.is_empty() && bytes.len() <= 16_384)?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    directory.sync_all().map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0)?;
    file.sync_all()
        .and_then(|_| directory.sync_all())
        .map_err(|_| REFUSED)?;
    Ok(())
}

// This is the only private PEM reader added by this profile. Its fixed two
// callers are infrastructure-owned CA/server key files, never application inputs.
fn read_key(directory: &File, name: &str, mode: u32) -> Result<KeyPair> {
    require((name, mode) == ("ca.key", 0o600) || (name, mode) == ("server.key", 0o640))?;
    let file = fs::open_child(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
    let meta = file.metadata().map_err(|_| REFUSED)?;
    require(
        meta.is_file()
            && meta.nlink() == 1
            && (1..=16_384).contains(&meta.len())
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.gid() == unsafe { libc::getegid() }
            && meta.mode() & 0o7777 == mode,
    )?;
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() as u64 == meta.len())?;
    let key = KeyPair::from_pem(std::str::from_utf8(&bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED)?;
    require(key.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256)?;
    Ok(key)
}

fn certificate(bytes: &[u8]) -> Result<Certificate> {
    require(
        bytes.len() <= 16_384
            && bytes.is_ascii()
            && !bytes.windows(11).any(|p| p == b"PRIVATE KEY"),
    )?;
    require(
        Certificate::load_pem_chain(bytes)
            .map_err(|_| REFUSED)?
            .len()
            == 1,
    )?;
    Certificate::from_pem(bytes).map_err(|_| REFUSED.into())
}

fn verify_leaf(
    ca_pem: &[u8],
    leaf_pem: &[u8],
    expected_spki: &str,
    observed: u64,
    permit_expired: bool,
) -> Result<u64> {
    use x509_cert::ext::pkix::{
        name::GeneralName, BasicConstraints as X509Constraints, ExtendedKeyUsage, KeyUsage,
        SubjectAltName,
    };
    let ca = certificate(ca_pem)?;
    let leaf = certificate(leaf_pem)?;
    let tbs = &leaf.tbs_certificate;
    let before = tbs.validity.not_before.to_unix_duration().as_secs();
    let after = tbs.validity.not_after.to_unix_duration().as_secs();
    require(
        tbs.subject.to_string() == "CN=postgres"
            && tbs.issuer == ca.tbs_certificate.subject
            && before < after
            && after - before == (LEAF_DAYS + 1) * 86400
            && before <= observed
            && digest(&tbs.subject_public_key_info.to_der().map_err(|_| REFUSED)?) == expected_spki,
    )?;
    require(
        tbs.get::<X509Constraints>()
            .map_err(|_| REFUSED)?
            .is_none_or(|(_, c)| !c.ca && c.path_len_constraint.is_none()),
    )?;
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(usage.digital_signature() && !usage.key_cert_sign() && !usage.crl_sign())?;
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(eku.0.len() == 1 && eku.0[0].to_string() == "1.3.6.1.5.5.7.3.1")?;
    let sans = tbs
        .get::<SubjectAltName>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(
        matches!(sans.0.as_slice(), [GeneralName::DnsName(name)] if name.as_str() == "postgres"),
    )?;
    let ca_der = CertificateDer::from(ca.to_der().map_err(|_| REFUSED)?);
    let leaf_der = CertificateDer::from(leaf.to_der().map_err(|_| REFUSED)?);
    let anchors = [webpki::anchor_from_trusted_cert(&ca_der).map_err(|_| REFUSED)?];
    let verifier = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| REFUSED)?;
    let at = if permit_expired && observed >= after {
        after.checked_sub(1).ok_or(REFUSED)?
    } else {
        observed
    };
    verifier
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(at)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| REFUSED)?;
    verifier
        .verify_is_valid_for_subject_name(&ServerName::try_from("postgres").map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED)?;
    Ok(after)
}

pub(crate) fn create(state: &mut InstallerState, installation: &Path) -> Result<Vec<u8>> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| view.require_path_binding(installation))?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    require(binding.profile == RuntimeProfile::Rootless && unsafe { libc::geteuid() } != 0)?;
    let engine_id = binding.engine_id.clone();
    let profile = state
        .journal()
        .feature_profile_sha256()
        .ok_or(REFUSED)?
        .to_owned();
    let id = state.journal().installation_id();
    let owner = state.create_feature_directory(DIRECTORY)?;
    let owner_identity = DirectoryIdentity::observe(&owner, 0o700)?;
    let server_name = CString::new("server").unwrap();
    require(unsafe { libc::mkdirat(owner.as_raw_fd(), server_name.as_ptr(), 0o750) } == 0)?;
    let server = fs::open_child(
        &owner,
        "server",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    // An operator umask must not accidentally make the fixed PostgreSQL group
    // unreadable; only this dedicated projection receives the explicit mode.
    require(unsafe { libc::fchmod(server.as_raw_fd(), 0o750) } == 0)?;
    let server_identity = DirectoryIdentity::observe(&server, 0o750)?;
    let observed = now()?;
    let ca_before = (observed / 86400 * 86400)
        .checked_sub(86400)
        .ok_or(REFUSED)?;
    let ca_after = ca_before + 3650 * 86400;
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|_| REFUSED)?;
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|_| REFUSED)?;
    let params = ca_params(id, ca_before, ca_after)?;
    let ca = params
        .self_signed(&ca_key)
        .map_err(|_| REFUSED)?
        .pem()
        .into_bytes();
    let leaf = leaf_pem(
        &server_key,
        &Issuer::from_params(&params, &ca_key),
        observed,
    )?;
    let spki = digest(&server_key.subject_public_key_info());
    verify_leaf(&ca, &leaf, &spki, observed, false)?;
    create_file(&owner, "ca.key", ca_key.serialize_pem().as_bytes(), 0o600)?;
    create_file(&owner, "ca.crt", &ca, 0o444)?;
    create_file(
        &server,
        "server.key",
        server_key.serialize_pem().as_bytes(),
        0o640,
    )?;
    create_file(&server, "server.crt", &leaf, 0o444)?;
    owner
        .sync_all()
        .and_then(|_| server.sync_all())
        .map_err(|_| REFUSED)?;
    fs::require_directory_binding(&installation.join(DIRECTORY), &owner, REFUSED)?;
    require(
        DirectoryIdentity::observe(&owner, 0o700)? == owner_identity
            && DirectoryIdentity::observe(&server, 0o750)? == server_identity,
    )?;
    let named_server = fs::open_child(
        &owner,
        "server",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    require(DirectoryIdentity::observe(&named_server, 0o750)? == server_identity)?;
    let receipt = Receipt {
        schema: SCHEMA.into(),
        installation_id: id,
        engine_id,
        feature_profile_sha256: profile,
        owner: owner_identity,
        server_projection: server_identity,
        ca_sha256: digest(&ca),
        ca_spki_sha256: digest(&ca_key.subject_public_key_info()),
        server_spki_sha256: spki,
        ca_not_before: ca_before,
        ca_not_after: ca_after,
        server_certificate_sha256: digest(&leaf),
        server_certificate_pem: String::from_utf8(leaf).map_err(|_| REFUSED)?,
    };
    state.write_evidence(RECORD, &serde_json::to_vec(&receipt).map_err(|_| REFUSED)?)?;
    state.with_inspection(|view| verify(view, installation))?;
    Ok(ca)
}

fn open_owner(
    view: &LockedInspection,
    installation: &Path,
    observed: u64,
    permit_expired: bool,
) -> Result<Owner> {
    view.require_path_binding(installation)?;
    let evidence = fs::open_child(
        view.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let result = open_owner_held(
        view.journal(),
        &evidence,
        installation,
        observed,
        permit_expired,
    )?;
    view.require_unchanged()?;
    Ok(result)
}

fn open_owner_held(
    journal: &Journal,
    evidence: &File,
    installation: &Path,
    observed: u64,
    permit_expired: bool,
) -> Result<Owner> {
    let receipt: Receipt = serde_json::from_value(
        crate::installer_json::decode(&fs::read_entry(evidence, RECORD, 0o600, false, REFUSED)?)
            .map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    require(
        receipt.schema == SCHEMA
            && receipt.installation_id == journal.installation_id()
            && journal.feature_profile_sha256() == Some(receipt.feature_profile_sha256.as_str())
            && journal.runtime().is_some_and(|r| {
                r.engine_id == receipt.engine_id && r.profile == RuntimeProfile::Rootless
            })
            && receipt.ca_not_after > observed + (LEAF_DAYS + 1) * 86400,
    )?;
    let path = installation.join(DIRECTORY);
    let directory = fs::directory(&path, REFUSED)?;
    let server = fs::open_child(
        &directory,
        "server",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let directory_now = DirectoryIdentity::observe(&directory, 0o700)?;
    let server_now = DirectoryIdentity::observe(&server, 0o750)?;
    require(
        receipt.owner.retained_matches(directory_now.clone())
            && receipt
                .server_projection
                .retained_matches(server_now.clone())
            && fs::file_names(&directory, REFUSED)?
                == BTreeSet::from(["ca.key".into(), "ca.crt".into(), "server".into()])
            && fs::file_names(&server, REFUSED)?
                == BTreeSet::from(["server.key".into(), "server.crt".into()]),
    )?;
    let ca_pem = fs::read_entry(&directory, "ca.crt", 0o444, false, REFUSED)?;
    let ca_key = read_key(&directory, "ca.key", 0o600)?;
    let server_key = read_key(&server, "server.key", 0o640)?;
    let ca = certificate(&ca_pem)?;
    require(
        digest(&ca_pem) == receipt.ca_sha256
            && digest(&ca_key.subject_public_key_info()) == receipt.ca_spki_sha256
            && ca
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| REFUSED)?
                == ca_key.subject_public_key_info()
            && digest(&server_key.subject_public_key_info()) == receipt.server_spki_sha256
            && ca.tbs_certificate.subject.to_string()
                == format!("CN=ElevenID managed PostgreSQL {}", receipt.installation_id)
            && ca
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                == receipt.ca_not_before
            && ca
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                == receipt.ca_not_after,
    )?;
    let leaf_pem = fs::read_entry(&server, "server.crt", 0o444, false, REFUSED)?;
    let (expected_leaf, sequence) = renewal::current_leaf(evidence, &receipt)?;
    require(digest(&expected_leaf) == digest(&leaf_pem) && expected_leaf == leaf_pem)?;
    let leaf_not_after = verify_leaf(
        &ca_pem,
        &leaf_pem,
        &receipt.server_spki_sha256,
        observed,
        permit_expired,
    )?;
    let result = Owner {
        path,
        directory,
        server,
        directory_now,
        server_now,
        receipt,
        ca_pem,
        ca_key,
        server_key,
        leaf_pem,
        leaf_not_after,
        sequence,
    };
    result.require_current()?;
    Ok(result)
}

impl Owner {
    fn require_current(&self) -> Result<()> {
        fs::require_directory_binding(&self.path, &self.directory, REFUSED)?;
        let named_server = fs::open_child(
            &self.directory,
            "server",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        require(
            DirectoryIdentity::observe(&self.directory, 0o700)? == self.directory_now
                && DirectoryIdentity::observe(&self.server, 0o750)? == self.server_now
                && DirectoryIdentity::observe(&named_server, 0o750)? == self.server_now,
        )
    }
}

pub(crate) fn verify(view: &LockedInspection, installation: &Path) -> Result<()> {
    open_owner(view, installation, now()?, false).map(|_| ())
}

/// Only the named renewal recovery entry point may retain an expired leaf. All
/// custody, key, issuer, name, exact receipt-chain and CA-lifetime checks remain
/// mandatory. This does not admit runtime work or a failed/pending renewal.
pub(crate) fn verify_for_renewal(view: &LockedInspection, installation: &Path) -> Result<()> {
    open_owner(view, installation, now()?, true).map(|_| ())
}

/// The Compose caller already holds the installation lock. Read-only admission
/// must not reacquire flock or adopt a changed path while checking custody.
pub(crate) fn verify_at(installation: &Path) -> Result<()> {
    let journal = InstallerState::inspect(installation)?;
    let held = fs::directory(installation, REFUSED)?;
    let evidence = fs::open_child(
        &held,
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    DirectoryIdentity::observe(&evidence, 0o700)?;
    open_owner_held(&journal, &evidence, installation, now()?, false)?;
    fs::require_directory_binding(installation, &held, REFUSED)?;
    require(InstallerState::inspect(installation)? == journal)
}

pub(crate) fn projection(installation: &Path) -> PathBuf {
    installation.join(DIRECTORY).join("server")
}

#[path = "installer_feature_postgres_tls_renewal.rs"]
mod renewal;
pub(crate) use renewal::renew;

#[cfg(test)]
#[path = "installer_feature_postgres_tls_tests.rs"]
mod tests;
