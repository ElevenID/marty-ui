//! Closed certificate roles shared by Gateway intent validation and the managed
//! certificate producer. A profile is never an arbitrary TBS/signing request.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateFamily {
    Icao,
    Mdoc,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCertificateProfile {
    IcaoCsca,
    IcaoDocumentSigner,
    MdocIaca,
    MdocDocumentSigner,
}

/// Public issuer information supplied by governed configuration, never guessed
/// from a DID or synthesized from the service's own hostname. A configured CRL
/// URL does not mean that this crate publishes or checks a CRL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocCertificateMetadata {
    pub issuer_contact_uri: String,
    pub crl_distribution_uri: String,
}

impl MdocCertificateMetadata {
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [&self.issuer_contact_uri, &self.crl_distribution_uri] {
            let uri = reqwest::Url::parse(value)
                .map_err(|_| "MDOC certificate publication configuration is invalid")?;
            if value.len() > 2048
                || !value.is_ascii()
                || value
                    .chars()
                    .any(|value| value.is_control() || value.is_whitespace())
                || !matches!(uri.scheme(), "http" | "https")
                || !uri.has_host()
                || !uri.username().is_empty()
                || uri.password().is_some()
                || uri.query().is_some()
                || uri.fragment().is_some()
            {
                return Err("MDOC certificate publication configuration is invalid");
            }
        }
        Ok(())
    }
}

impl ManagedCertificateProfile {
    pub fn from_identity(purpose: &str, format: &str) -> Option<Self> {
        match (purpose, format.to_ascii_uppercase().as_str()) {
            ("csca", "ICAO_EMRTD") => Some(Self::IcaoCsca),
            ("x509_doc_signer", "ICAO_EMRTD") => Some(Self::IcaoDocumentSigner),
            ("mdoc_iaca", "MDOC") => Some(Self::MdocIaca),
            ("mdoc_dsc", "MDOC") => Some(Self::MdocDocumentSigner),
            _ => None,
        }
    }

    pub const fn family(self) -> CertificateFamily {
        match self {
            Self::IcaoCsca | Self::IcaoDocumentSigner => CertificateFamily::Icao,
            Self::MdocIaca | Self::MdocDocumentSigner => CertificateFamily::Mdoc,
        }
    }

    pub const fn key_purpose(self) -> &'static str {
        match self {
            Self::IcaoCsca => "csca",
            Self::IcaoDocumentSigner => "x509_doc_signer",
            Self::MdocIaca => "mdoc_iaca",
            Self::MdocDocumentSigner => "mdoc_dsc",
        }
    }

    pub const fn authority(self) -> Self {
        match self.family() {
            CertificateFamily::Icao => Self::IcaoCsca,
            CertificateFamily::Mdoc => Self::MdocIaca,
        }
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::IcaoCsca | Self::MdocIaca)
    }

    pub const fn credential_format(self) -> &'static str {
        match self.family() {
            CertificateFamily::Icao => "ICAO_EMRTD",
            CertificateFamily::Mdoc => "MDOC",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_families_do_not_alias_passport_and_mdoc_authority() {
        for (purpose, format) in [
            ("csca", "MDOC"),
            ("mdoc_iaca", "ICAO_EMRTD"),
            ("x509_doc_signer", "MDOC"),
            ("mdoc_dsc", "ICAO_EMRTD"),
        ] {
            assert!(ManagedCertificateProfile::from_identity(purpose, format).is_none());
        }
        assert_eq!(
            ManagedCertificateProfile::from_identity("mdoc_dsc", "mdoc")
                .unwrap()
                .authority(),
            ManagedCertificateProfile::MdocIaca
        );
    }
}
