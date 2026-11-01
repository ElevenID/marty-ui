//! Provider-neutral hosting inputs for the signed installer. Selection is
//! journal-bound before ingress provisioning; it never provisions DNS, firewall
//! rules, cloud resources, or a different key-custody implementation.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{BoundFile, ComposeInputs},
    installer_host_fs as fs,
    installer_state::{InstallerState, LockedInspection, Phase},
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "hosting inputs are absent, changed or unsupported; preserve installation evidence";
pub(crate) const RECORD: &str = "hosting-selection.json";
pub(crate) const SOURCE: &str = "hosting-input.json";
pub(crate) const CONNECTOR_TOKEN: &str = "cloudflare_tunnel_token";
const SCHEMA: &str = "elevenid.installation-hosting/v1";
const SELECTION_SCHEMA: &str = "elevenid.installation-hosting-selection/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Local,
    Direct,
    ExternalProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub bind_address: IpAddr,
    pub port: u16,
}

impl Listener {
    pub fn socket_address(self) -> SocketAddr {
        SocketAddr::new(self.bind_address, self.port)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateSource {
    ManagedCa,
    FoundationImport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Termination {
    MartyKeyless,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    termination: Termination,
    certificate_source: CertificateSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorKind {
    CloudflareTunnel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connector {
    pub kind: ConnectorKind,
    pub token_file: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_origin: Option<PublicOrigin>,
    /// An optional IP transport alias for the public entry page. It never
    /// changes the canonical application origin or the issuer identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_entry_origin: Option<PublicOrigin>,
    listener: Listener,
    tls: Tls,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connector: Option<Connector>,
}

/// Private input bytes stay here until the authenticated installer records the
/// selected configuration. No token bytes are retained or serialized.
pub(crate) struct Prepared {
    raw: Vec<u8>,
    configuration: Configuration,
    connector_token_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha256: String,
    configuration: Configuration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connector_token_sha256: Option<String>,
    #[serde(skip)]
    recorded: bool,
}

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

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn path_is_safe(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.to_str().is_some_and(|text| {
            !text.ends_with('/')
                && !text
                    .chars()
                    .any(|c| c.is_control() || c == '\'' || c == '\\')
                && text
                    .split('/')
                    .skip(1)
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        })
}

fn private_bytes(path: &Path) -> Result<Vec<u8>> {
    require(path_is_safe(path))?;
    let parent = fs::directory(path.parent().ok_or(REFUSED)?, REFUSED)?;
    let value = fs::read_entry(
        &parent,
        path.file_name().and_then(|s| s.to_str()).ok_or(REFUSED)?,
        0o600,
        false,
        REFUSED,
    )?;
    fs::require_directory_binding(path.parent().ok_or(REFUSED)?, &parent, REFUSED)?;
    Ok(value)
}

fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    require(!raw.is_empty() && raw.len() <= 65_536)?;
    serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

fn token(path: &Path) -> Result<Vec<u8>> {
    let bytes = private_bytes(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| REFUSED)?
        .trim_end_matches(['\r', '\n']);
    require(
        (16..=16_384).contains(&bytes.len())
            && text.len() >= 16
            && text
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_=+./".contains(&c)),
    )?;
    Ok(bytes)
}

impl Configuration {
    fn local(foundation_origin: Option<PublicOrigin>) -> Result<Self> {
        if let Some(origin) = &foundation_origin {
            require(origin.is_loopback() && origin.port() >= 1024)?;
        }
        Ok(Self {
            schema: SCHEMA.into(),
            mode: Mode::Local,
            listener: Listener {
                bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: foundation_origin.as_ref().map_or(0, PublicOrigin::port),
            },
            tls: Tls {
                termination: Termination::MartyKeyless,
                certificate_source: if foundation_origin.is_some() {
                    CertificateSource::FoundationImport
                } else {
                    CertificateSource::ManagedCa
                },
            },
            public_origin: foundation_origin,
            public_entry_origin: None,
            connector: None,
        })
    }

    fn validate(&self) -> Result<()> {
        // The transport/SAN parser supports IPv6, but the application's current
        // did:web authority contract does not. Refuse that public identity here
        // before provisioning rather than accepting an origin the gateway will
        // reject at startup. DNS origins may still use an IPv6 listener.
        if matches!(
            self.public_origin
                .as_ref()
                .and_then(PublicOrigin::ip_address),
            Some(IpAddr::V6(_))
        ) {
            return Err("public IPv6 literal origins are not supported by the installer application identity contract; use a DNS origin with an IPv6 listener".into());
        }
        require(
            self.schema == SCHEMA
                && !self.listener.bind_address.is_multicast()
                && self.listener.bind_address != IpAddr::V4(Ipv4Addr::BROADCAST)
                && !matches!(self.listener.bind_address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()),
        )?;
        match self.mode {
            Mode::Local => {
                require(self.listener.bind_address.is_loopback() && self.connector.is_none())?;
                match &self.public_origin {
                    None => require(self.listener.port == 0)?,
                    Some(origin) => require(
                        origin.is_loopback()
                            && origin.port() == self.listener.port
                            && self.listener.port >= 1024
                            && origin
                                .ip_address()
                                .is_none_or(|ip| ip == self.listener.bind_address),
                    )?,
                }
            }
            Mode::Direct => require(
                self.listener.port >= 1024
                    && !self.listener.bind_address.is_loopback()
                    && self
                        .public_origin
                        .as_ref()
                        .is_some_and(|origin| !origin.is_loopback())
                    && self.connector.is_none(),
            )?,
            Mode::ExternalProxy => require(
                self.listener.port >= 1024
                    && self
                        .public_origin
                        .as_ref()
                        .is_some_and(|origin| !origin.is_loopback()),
            )?,
        }
        if let Some(connector) = &self.connector {
            require(self.mode == Mode::ExternalProxy && path_is_safe(&connector.token_file))?;
        }
        if let Some(alias) = &self.public_entry_origin {
            if self.tls.certificate_source != CertificateSource::ManagedCa {
                return Err("public_entry_origin requires managed-ca certificate issuance with DNS and IP SAN coverage; foundation-import does not support an IP entry alias".into());
            }
            require(
                self.mode == Mode::Direct
                    && self
                        .public_origin
                        .as_ref()
                        .is_some_and(|origin| origin.dns_name().is_some() && !origin.is_loopback())
                    && alias.ip_address().is_some()
                    && !alias.is_loopback(),
            )?;
        }
        Ok(())
    }

    /// Only new installations apply this identity guard. Recorded legacy
    /// selections remain inspectable without silently rewriting their origin.
    fn validate_installation(&self) -> Result<()> {
        self.validate()?;
        if let Some(origin) = &self.public_origin {
            origin.did_web_authority().map_err(|_| {
                "new installations require a DNS canonical origin for did:web; configure a direct public_entry_origin for IP page access, and preserve an existing installation for a separately supported identity migration".to_string()
            })?;
        }
        Ok(())
    }

    fn require_foundation(&self, foundation_origin: Option<&PublicOrigin>) -> Result<()> {
        match (self.tls.certificate_source, foundation_origin) {
            (CertificateSource::ManagedCa, None) => Ok(()),
            (CertificateSource::FoundationImport, Some(origin)) => {
                require(self.public_origin.as_ref() == Some(origin))
            }
            _ => Err("hosting certificate source must match the selected managed OpenBao or imported foundation".into()),
        }
    }
}

/// Validate user files before confirmation or runtime side effects. Foundation
/// origin is read by its existing owner; hosting never creates KMS resources.
pub(crate) fn prepare(
    path: Option<&Path>,
    foundation_origin: Option<PublicOrigin>,
) -> Result<Prepared> {
    let (raw, configuration) = if let Some(path) = path {
        let raw = private_bytes(path)?;
        let configuration: Configuration = decode(&raw)?;
        (raw, configuration)
    } else {
        let configuration = Configuration::local(foundation_origin.clone())?;
        let raw = serde_json::to_vec(&configuration).map_err(|_| REFUSED)?;
        (raw, configuration)
    };
    configuration.validate_installation()?;
    configuration.require_foundation(foundation_origin.as_ref())?;
    let connector_token_sha256 = configuration
        .connector
        .as_ref()
        .map(|connector| token(&connector.token_file).map(|bytes| digest(&bytes)))
        .transpose()?;
    Ok(Prepared {
        raw,
        configuration,
        connector_token_sha256,
    })
}

impl Prepared {
    pub(crate) fn host_impact(&self) -> String {
        let origin = self
            .configuration
            .public_origin
            .as_ref()
            .map(PublicOrigin::as_str)
            .unwrap_or("https://localhost:<selected-port>");
        format!(
            "public origin {origin}; public entry origin {}; ingress listener {}; public TLS owner {}; connector {}",
            self.configuration
                .public_entry_origin
                .as_ref()
                .map(PublicOrigin::as_str)
                .unwrap_or("none"),
            self.configuration.listener.socket_address(),
            if self.configuration.mode == Mode::ExternalProxy {
                "external proxy"
            } else {
                "Marty keyless edge"
            },
            if self.configuration.connector.is_some() {
                "Cloudflare Tunnel (explicit selection)"
            } else {
                "none"
            }
        )
    }
}

pub(crate) fn select(prepared: Prepared, state: &mut InstallerState) -> Result<Selection> {
    state.require_live_phase(Phase::Verified)?;
    prepared.configuration.validate_installation()?;
    let foundation = state.with_inspection(crate::installer_foundation::load)?;
    let foundation_origin = foundation
        .as_ref()
        .map(|v| PublicOrigin::parse(&v.configuration.public_origin))
        .transpose()?;
    prepared
        .configuration
        .require_foundation(foundation_origin.as_ref())?;
    let selection = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&prepared.raw),
        configuration: prepared.configuration,
        connector_token_sha256: prepared.connector_token_sha256,
        recorded: true,
    };
    let raw = serde_json::to_vec(&selection).map_err(|_| REFUSED)?;
    state.write_evidence(SOURCE, &prepared.raw)?;
    state.write_evidence(RECORD, &raw)?;
    state.bind_hosting_selection(&digest(&raw))?;
    state.with_inspection(|view| {
        let confirmed = load(view)?.ok_or(REFUSED)?;
        require(confirmed.source_sha256 == selection.source_sha256)
    })?;
    Ok(selection)
}

pub(crate) fn load(state: &LockedInspection) -> Result<Option<Selection>> {
    let raw = state.diagnostic_record(RECORD, true)?;
    let source = state.diagnostic_record(SOURCE, true)?;
    let Some(expected) = state.journal().hosting_selection_sha256() else {
        require(raw.is_none() && source.is_none())?;
        return Ok(None);
    };
    let raw = raw.ok_or(REFUSED)?;
    let source = source.ok_or(REFUSED)?;
    let selection = decode_selection(&raw, &source, state.journal().installation_id(), expected)?;
    let foundation = crate::installer_foundation::load(state)?;
    let origin = foundation
        .as_ref()
        .map(|v| PublicOrigin::parse(&v.configuration.public_origin))
        .transpose()?;
    selection
        .configuration
        .require_foundation(origin.as_ref())?;
    Ok(Some(selection))
}

fn decode_selection(
    raw: &[u8],
    source: &[u8],
    installation_id: uuid::Uuid,
    expected: &str,
) -> Result<Selection> {
    require(digest(raw) == expected)?;
    let mut selection: Selection = decode(raw)?;
    let configuration: Configuration = decode(source)?;
    selection.configuration.validate()?;
    require(
        selection.schema == SELECTION_SCHEMA
            && selection.installation_id == installation_id
            && valid_digest(&selection.source_sha256)
            && selection.source_sha256 == digest(source)
            && selection.configuration == configuration
            && selection.configuration.connector.is_some()
                == selection.connector_token_sha256.is_some()
            && selection
                .connector_token_sha256
                .as_deref()
                .is_none_or(valid_digest),
    )?;
    selection.recorded = true;
    Ok(selection)
}

/// Compose must admit the exact journal-bound selection, not a caller-supplied
/// port allowance. Reads do not acquire another lock while the writer owns it.
pub(crate) fn for_inputs(inputs: &ComposeInputs) -> Result<Option<Selection>> {
    let journal = InstallerState::inspect(&inputs.installation)?;
    let source_path = inputs.installation.join("evidence").join(SOURCE);
    let record_path = inputs.installation.join("evidence").join(RECORD);
    let Some(expected) = journal.hosting_selection_sha256() else {
        for path in [&source_path, &record_path] {
            require(!inputs.bound_inputs.iter().any(|file| &file.path == path))?;
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(REFUSED.into()),
            }
        }
        return Ok(None);
    };
    require(inputs.project == journal.compose_project())?;
    let raw = private_bytes(&record_path)?;
    let source = private_bytes(&source_path)?;
    for (path, bytes) in [(&record_path, &raw), (&source_path, &source)] {
        let matching: Vec<_> = inputs
            .bound_inputs
            .iter()
            .filter(|file| &file.path == path)
            .collect();
        require(matching.len() == 1 && matching[0].sha256 == digest(bytes))?;
    }
    let selection = decode_selection(&raw, &source, journal.installation_id(), expected)?;
    let foundation = crate::installer_foundation::for_inputs(inputs)?;
    let origin = foundation
        .as_ref()
        .map(|v| PublicOrigin::parse(&v.configuration.public_origin))
        .transpose()?;
    selection
        .configuration
        .require_foundation(origin.as_ref())?;
    Ok(Some(selection))
}

/// Missing selection is permitted only for an old journal without the new
/// marker. That fallback is always loopback, including legacy AWS foundation.
pub(crate) fn resolve(state: &LockedInspection) -> Result<Selection> {
    if let Some(selection) = load(state)? {
        return Ok(selection);
    }
    let foundation = crate::installer_foundation::load(state)?;
    let origin = foundation
        .as_ref()
        .map(|v| PublicOrigin::parse(&v.configuration.public_origin))
        .transpose()?;
    let configuration = Configuration::local(origin)?;
    configuration.validate()?;
    let raw = serde_json::to_vec(&configuration).map_err(|_| REFUSED)?;
    Ok(Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&raw),
        configuration,
        connector_token_sha256: None,
        recorded: false,
    })
}

impl Selection {
    pub(crate) fn is_recorded(&self) -> bool {
        self.recorded
    }
    pub fn mode(&self) -> Mode {
        self.configuration.mode
    }
    pub fn requested_origin(&self) -> Option<&PublicOrigin> {
        self.configuration.public_origin.as_ref()
    }
    pub fn public_entry_origin(&self) -> Option<&PublicOrigin> {
        self.configuration.public_entry_origin.as_ref()
    }
    pub fn listener(&self) -> Listener {
        self.configuration.listener
    }
    pub fn certificate_source(&self) -> CertificateSource {
        self.configuration.tls.certificate_source
    }
    pub fn connector(&self) -> Option<&Connector> {
        self.configuration.connector.as_ref()
    }
    /// Frontend TLS belongs to the external proxy. The owned backend continues
    /// to use the keyless edge and its separately validated certificate.
    pub fn external_tls_owned(&self) -> bool {
        self.mode() == Mode::ExternalProxy
    }
    pub fn certificate_dns_name(&self) -> Option<&str> {
        self.requested_origin()
            .map_or(Some("localhost"), PublicOrigin::dns_name)
    }
    pub fn certificate_ip_address(&self) -> Option<IpAddr> {
        if let Some(alias) = self.public_entry_origin() {
            return alias.ip_address();
        }
        self.requested_origin()
            .map_or(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), |origin| {
                origin.ip_address().or_else(|| {
                    (origin.host() == "localhost").then_some(IpAddr::V4(Ipv4Addr::LOCALHOST))
                })
            })
    }
    pub fn resolve_origin(&self, listener_port: u16) -> Result<PublicOrigin> {
        require(
            listener_port >= 1024
                && (self.listener().port == 0 || self.listener().port == listener_port),
        )?;
        self.requested_origin().cloned().map_or_else(
            || PublicOrigin::parse(&format!("https://localhost:{listener_port}")),
            Ok,
        )
    }
    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) -> Result<()> {
        if !self.recorded {
            return Ok(());
        }
        for name in [SOURCE, RECORD] {
            inputs
                .bound_inputs
                .push(crate::installer_application::bound(
                    inputs.installation.join("evidence").join(name),
                )?);
        }
        Ok(())
    }
    pub(crate) fn import_connector(&self, state: &mut InstallerState) -> Result<()> {
        if let Some(connector) = self.connector() {
            let value = token(&connector.token_file)?;
            require(self.connector_token_sha256.as_deref() == Some(digest(&value).as_str()))?;
            state.stage_application_inputs(&BTreeMap::from([(CONNECTOR_TOKEN.into(), value)]))?;
        }
        Ok(())
    }
    pub(crate) fn bind_connector(&self, inputs: &mut ComposeInputs) -> Result<()> {
        if let Some(expected) = &self.connector_token_sha256 {
            inputs.bound_inputs.push(BoundFile {
                path: inputs.installation.join("secrets").join(CONNECTOR_TOKEN),
                sha256: expected.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "installer_hosting_tests.rs"]
mod tests;
