//! Explicit public ACME inputs bound to the authenticated hosting selection.
//! Selection records exact customer agreement and performs no CA request.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_certificates::CertificateIdentity,
    installer_hosting::{self, CertificateSource, Mode},
    installer_ingress_provision::IngressIdentity,
    installer_state::LockedInspection,
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME configuration refused; use an explicit supported Let's Encrypt environment and directory, shortlived profile, agreed terms URL, and recorded direct DNS hosting";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeEnvironment {
    Staging,
    Production,
}
impl AcmeEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
    pub fn directory_url(self) -> &'static str {
        match self {
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            Self::Production => "https://acme-v02.api.letsencrypt.org/directory",
        }
    }
}

/// No environment, agreement or contact is inferred. A missing contact is
/// normal: Let's Encrypt no longer stores account email for expiry notices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeParameters {
    environment: AcmeEnvironment,
    directory_url: String,
    profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contact: Option<String>,
    terms_url: String,
    terms_agreed: bool,
}
impl AcmeParameters {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require(!bytes.is_empty() && bytes.len() <= 8192)?;
        let value = crate::installer_json::decode(bytes).map_err(|_| REFUSED)?;
        let parameters: Self = serde_json::from_value(value).map_err(|_| REFUSED)?;
        parameters.validate()?;
        Ok(parameters)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            self.directory_url == self.environment.directory_url()
                && self.profile == "shortlived"
                && self.terms_agreed,
        )?;
        require(self.terms_url.is_ascii() && self.terms_url.len() <= 2048)?;
        let terms = reqwest::Url::parse(&self.terms_url).map_err(|_| REFUSED)?;
        require(
            terms.as_str() == self.terms_url
                && terms.scheme() == "https"
                && terms.host_str() == Some("letsencrypt.org")
                && terms.port().is_none()
                && terms.username().is_empty()
                && terms.password().is_none()
                && terms.query().is_none()
                && terms.fragment().is_none()
                && terms.path().starts_with("/documents/")
                && terms.path().ends_with(".pdf"),
        )?;
        if let Some(contact) = &self.contact {
            require(contact.is_ascii() && contact.len() <= 261)?;
            let mailbox = contact.strip_prefix("mailto:").ok_or(REFUSED)?;
            let (local, domain) = mailbox.rsplit_once('@').ok_or(REFUSED)?;
            require(
                !local.is_empty()
                    && local.len() <= 64
                    && !local.starts_with('.')
                    && !local.ends_with('.')
                    && !local.contains("..")
                    && local
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
            )?;
            let origin = PublicOrigin::parse(&format!("https://{domain}")).map_err(|_| REFUSED)?;
            require(origin.dns_name() == Some(domain) && !origin.is_loopback())?;
            origin.did_web_authority().map_err(|_| REFUSED)?;
        }
        Ok(())
    }
    pub fn environment(&self) -> AcmeEnvironment {
        self.environment
    }
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }
    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub fn contact(&self) -> Option<&str> {
        self.contact.as_deref()
    }
    pub fn terms_url(&self) -> &str {
        &self.terms_url
    }
    /// Registration must use the directory instance whose metadata was checked.
    /// Agreement is not permission to accept a later changed terms document.
    pub fn require_directory_terms(&self, observed: Option<&str>) -> Result<()> {
        self.validate()?;
        require(observed == Some(self.terms_url.as_str()))
    }
}

/// Freshly reconstructed from the held installation and exact hosting record.
/// There is deliberately no Deserialize implementation for this admission type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BoundAcmeConfiguration {
    schema: &'static str,
    installation_id: uuid::Uuid,
    hosting_selection_sha256: String,
    canonical_origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_entry_origin: Option<String>,
    parameters: AcmeParameters,
}
impl BoundAcmeConfiguration {
    pub fn from_selection(state: &LockedInspection) -> Result<Self> {
        let hosting = installer_hosting::load(state)?.ok_or(REFUSED)?;
        Self::bind(state, hosting.acme_parameters().cloned().ok_or(REFUSED)?)
    }
    pub fn bind(state: &LockedInspection, parameters: AcmeParameters) -> Result<Self> {
        state.require_unchanged()?;
        parameters.validate()?;
        let hosting = installer_hosting::load(state)?.ok_or(REFUSED)?;
        require(
            hosting.is_recorded()
                && hosting.mode() == Mode::Direct
                && hosting.certificate_source() == CertificateSource::Acme
                && hosting.acme_parameters() == Some(&parameters)
                && hosting.http01_host_port().is_some()
                && hosting.connector().is_none(),
        )?;
        let origin = hosting.requested_origin().ok_or(REFUSED)?;
        require(origin.dns_name().is_some() && !origin.is_loopback())?;
        origin.did_web_authority().map_err(|_| REFUSED)?;
        CertificateIdentity::from_ingress(&IngressIdentity::new(
            hosting.certificate_dns_name(),
            hosting.certificate_ip_address(),
        )?)?;
        let binding = Self {
            schema: "elevenid.installer-acme-configuration/v1",
            installation_id: state.journal().installation_id(),
            hosting_selection_sha256: state
                .journal()
                .hosting_selection_sha256()
                .ok_or(REFUSED)?
                .to_owned(),
            canonical_origin: origin.as_str().to_owned(),
            public_entry_origin: hosting
                .public_entry_origin()
                .map(|origin| origin.as_str().into()),
            parameters,
        };
        state.require_unchanged()?;
        Ok(binding)
    }
    pub fn parameters(&self) -> &AcmeParameters {
        &self.parameters
    }
    pub fn installation_id(&self) -> uuid::Uuid {
        self.installation_id
    }
    pub fn hosting_selection_sha256(&self) -> &str {
        &self.hosting_selection_sha256
    }
    pub fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }
    pub fn public_entry_origin(&self) -> Option<&str> {
        self.public_entry_origin.as_deref()
    }
    pub fn certificate_identity(&self) -> Result<CertificateIdentity> {
        let origin = PublicOrigin::parse(&self.canonical_origin).map_err(|_| REFUSED)?;
        let ip = self
            .public_entry_origin
            .as_deref()
            .map(PublicOrigin::parse)
            .transpose()?
            .and_then(|origin| origin.ip_address());
        CertificateIdentity::from_ingress(&IngressIdentity::new(origin.dns_name(), ip)?)
    }
}

#[cfg(test)]
#[path = "installer_acme_configuration_tests.rs"]
mod tests;
