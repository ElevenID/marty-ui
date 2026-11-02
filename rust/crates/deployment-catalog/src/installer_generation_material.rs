//! Source-specific ingress evidence and clocks. Public trust and the retained
//! installation CA remain separate validators throughout generation recovery.
use super::*;
use crate::{
    installer_ingress_outputs::IngressMetadata,
    installer_ingress_provision::{self as ingress, IngressIdentity},
    installer_public_ingress::PublicIngressMetadata,
    operator_certificates::{check_chain_at, check_lifetime_at},
};
use spki::der::{Encode, EncodePem};
use std::time::Duration;

#[derive(Clone)]
pub(crate) enum GenerationMaterial {
    Public(Box<PublicIngressMetadata>),
    Managed(Box<IngressMetadata>),
}
impl GenerationMaterial {
    pub(crate) fn load(installation: &Path, binding: &GenerationBinding) -> Result<Self> {
        if binding.public_ingress() {
            Ok(Self::Public(Box::new(
                binding
                    .public_ingress_metadata(installation)?
                    .ok_or(REFUSED)?,
            )))
        } else {
            require(binding.managed_ingress())?;
            Ok(Self::Managed(Box::new(
                binding.ingress_metadata(installation)?.ok_or(REFUSED)?,
            )))
        }
    }
    pub(crate) fn observed_at(&self) -> u64 {
        match self {
            Self::Public(value) => value.token_observed_at,
            Self::Managed(value) => value.token_observed_at,
        }
    }
    pub(crate) fn ttl(&self) -> u64 {
        match self {
            Self::Public(value) => value.token_ttl_seconds,
            Self::Managed(value) => value.token_ttl_seconds,
        }
    }
    pub(crate) fn expires_at(&self) -> Result<u64> {
        match self {
            Self::Public(value) => value.certificate_admission["not_after"]
                .as_u64()
                .ok_or_else(|| REFUSED.into()),
            Self::Managed(value) => Ok(value.certificate_expires_at),
        }
    }
    pub(crate) fn not_before(
        &self,
        installation: &Path,
        binding: &GenerationBinding,
    ) -> Result<u64> {
        match self {
            Self::Public(value) => value.certificate_admission["not_before"]
                .as_u64()
                .ok_or_else(|| REFUSED.into()),
            Self::Managed(_) => {
                let bytes = binding.read(installation, ingress::OUTPUTS[1])?;
                let cert = ingress::certificate(std::str::from_utf8(&bytes).map_err(|_| REFUSED)?)?;
                Ok(cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs())
            }
        }
    }
    pub(crate) fn validate_historical(
        &self,
        installation: &Path,
        binding: &GenerationBinding,
    ) -> Result<()> {
        match self {
            Self::Public(value) => {
                require(binding.public_ingress())?;
                value
                    .validate_selected_at(
                        &binding.read(installation, "installer_ingress_tls_cert")?,
                        value.token_observed_at,
                    )
                    .map(|_| ())
            }
            Self::Managed(value) => validate_private(installation, binding, value),
        }
    }
    pub(crate) fn validate_selected_at(
        &self,
        installation: &Path,
        binding: &GenerationBinding,
        at: u64,
    ) -> Result<()> {
        self.validate_historical(installation, binding)?;
        match self {
            Self::Public(value) => value
                .validate_selected_at(
                    &binding.read(installation, "installer_ingress_tls_cert")?,
                    at,
                )
                .map(|_| ()),
            Self::Managed(value) => {
                require(
                    at >= self.not_before(installation, binding)?
                        && at < value.ca_expires_at
                        && at < value.certificate_expires_at,
                )?;
                let ca = binding.read(installation, ingress::OUTPUTS[0])?;
                let leaf = binding.read(installation, ingress::OUTPUTS[1])?;
                require(
                    check_lifetime_at(&ca, 0, Duration::from_secs(at)).map_err(|_| REFUSED)?
                        && check_lifetime_at(&leaf, 0, Duration::from_secs(at))
                            .map_err(|_| REFUSED)?,
                )?;
                check_chain_at(&leaf, &ca, Duration::from_secs(at)).map_err(|_| REFUSED.into())
            }
        }
    }
    pub(crate) fn require_issuer_lifetime(
        &self,
        installation: &Path,
        binding: &GenerationBinding,
        at: u64,
    ) -> Result<()> {
        self.validate_historical(installation, binding)?;
        if let Self::Managed(value) = self {
            // Historical source expiry is permitted, but a backwards clock
            // must not authorize a new mint before its retained observation.
            super::schedule::credential_due(value.token_observed_at, value.token_ttl_seconds, at)?;
            require(at >= self.not_before(installation, binding)?)?;
            // The retained issuer is never renewed, rotated or repaired here.
            // The existing fixed producer asks for the same eight-hour leaf.
            if value.ca_expires_at < at.checked_add(28_800).ok_or(REFUSED)? {
                return Err("The retained private issuer cannot cover another generation; issuer rotation requires a separately supported operation".into());
            }
        }
        Ok(())
    }
}

fn validate_private(
    installation: &Path,
    binding: &GenerationBinding,
    metadata: &IngressMetadata,
) -> Result<()> {
    require(binding.managed_ingress())?;
    let identity = IngressIdentity::from_metadata(&metadata.dns_names, &metadata.ip_addresses)?;
    let expected = crate::installer_ingress_outputs::metadata_for_identity(
        &encode(metadata)?,
        &binding.installation_id,
        metadata.token_observed_at,
        &identity,
    )?;
    require(&expected == metadata)?;
    let ca = binding.read(installation, ingress::OUTPUTS[0])?;
    let leaf = binding.read(installation, ingress::OUTPUTS[1])?;
    let ca_text = std::str::from_utf8(&ca).map_err(|_| REFUSED)?;
    let leaf_text = std::str::from_utf8(&leaf).map_err(|_| REFUSED)?;
    let issuer = ingress::certificate(ca_text)?;
    let certificate = ingress::certificate(leaf_text)?;
    let public = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    require(
        ingress::check_certificates_for(
            ca_text,
            leaf_text,
            &public,
            &ingress::resource_name(&binding.installation_id)?,
            metadata.token_observed_at,
            &identity,
        )? == (metadata.ca_expires_at, metadata.certificate_expires_at)
            && metadata.ca_pem_sha256 == hash(&ca)
            && metadata.certificate_pem_sha256 == hash(&leaf)
            && metadata.ca_der_sha256 == hash(&issuer.to_der().map_err(|_| REFUSED)?)
            && metadata.certificate_der_sha256 == hash(&certificate.to_der().map_err(|_| REFUSED)?),
    )
}
