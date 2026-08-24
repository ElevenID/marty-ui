use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::form_urlencoded;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialFormat {
    Mdoc,
    SdJwtVc,
    VcJwt,
    JsonLd,
    ZkMdoc,
    VdsNc,
}

impl CredentialFormat {
    pub fn parse(value: &str) -> Result<Self, CredentialTemplateError> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "mdoc" | "mso_mdoc" => Ok(Self::Mdoc),
            "sd_jwt_vc" | "vc+sd_jwt" | "dc+sd_jwt" | "spruce_vc+sd_jwt" | "sd_jwt"
            | "ietf_sd_jwt" => Ok(Self::SdJwtVc),
            "vc_jwt" | "jwt_vc" | "jwt_vc_json" | "jwt_vc_json_ld" => Ok(Self::VcJwt),
            "jsonld" | "json_ld" | "ldp_vc" => Ok(Self::JsonLd),
            "zk_mdoc" | "zkp_mdoc" => Ok(Self::ZkMdoc),
            "vds_nc" | "vds_nc_barcode" => Ok(Self::VdsNc),
            _ => Err(CredentialTemplateError::InvalidFormat(value.to_owned())),
        }
    }

    #[must_use]
    pub const fn canonical(self) -> &'static str {
        match self {
            Self::Mdoc => "MDOC",
            Self::SdJwtVc => "SD_JWT_VC",
            Self::VcJwt => "VC_JWT",
            Self::JsonLd => "JSON_LD",
            Self::ZkMdoc => "ZK_MDOC",
            Self::VdsNc => "VDS_NC",
        }
    }

    #[must_use]
    pub const fn public_wire(self) -> &'static str {
        match self {
            Self::Mdoc => "mdoc",
            Self::SdJwtVc => "sd_jwt_vc",
            Self::VcJwt => "jwt_vc",
            Self::JsonLd => "ldp_vc",
            Self::ZkMdoc => "zk_mdoc",
            Self::VdsNc => "vds_nc",
        }
    }

    #[must_use]
    pub const fn signing_wire(self) -> &'static str {
        match self {
            Self::Mdoc => "mso_mdoc",
            Self::SdJwtVc => "dc+sd-jwt",
            Self::VcJwt => "jwt_vc_json",
            Self::JsonLd => "ldp_vc",
            Self::ZkMdoc => "zk_mdoc",
            Self::VdsNc => "vds_nc",
        }
    }
}

pub fn normalize_payload_format(
    value: Option<&str>,
    supported_formats: &[CredentialFormat],
) -> Result<CredentialFormat, CredentialTemplateError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            let normalized = value.to_ascii_lowercase();
            match normalized.as_str() {
                "sd_jwt_vc" | "sd-jwt-vc" | "vc+sd-jwt" | "dc+sd-jwt" | "ietf_sd_jwt"
                | "w3c_vcdm_v2_sd_jwt" => Ok(CredentialFormat::SdJwtVc),
                "mdoc" | "mso_mdoc" => Ok(CredentialFormat::Mdoc),
                "vc_jwt" | "jwt_vc" | "jwt_vc_json" | "jwt_vc_json-ld" | "w3c_vcdm_v2_jwt_vc" => {
                    Ok(CredentialFormat::VcJwt)
                }
                "json_ld" | "json-ld" | "ldp_vc" => Ok(CredentialFormat::JsonLd),
                _ => CredentialFormat::parse(value),
            }
        }
        None => Ok(supported_formats
            .first()
            .copied()
            .unwrap_or(CredentialFormat::SdJwtVc)),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuanceProtocol {
    Oid4vciPreAuth,
    Oid4vciAuthCode,
}

impl IssuanceProtocol {
    pub fn parse(value: Option<&str>) -> Result<Self, CredentialTemplateError> {
        let normalized = value
            .unwrap_or("OID4VCI_PRE_AUTH")
            .trim()
            .to_ascii_uppercase();
        match normalized.as_str() {
            "OID4VCI"
            | "OID4VCI_PRE_AUTH"
            | "OID4VCI_PRE_AUTHORIZED"
            | "OID4VCI_PREAUTHORIZED"
            | "OID4VCI_PRE_AUTH_CODE" => Ok(Self::Oid4vciPreAuth),
            "OID4VCI_AUTH_CODE" | "OID4VCI_AUTHORIZATION_CODE" => Ok(Self::Oid4vciAuthCode),
            _ => Err(CredentialTemplateError::InvalidIssuanceProtocol(normalized)),
        }
    }

    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Oid4vciPreAuth => "OID4VCI_PRE_AUTH",
            Self::Oid4vciAuthCode => "OID4VCI_AUTH_CODE",
        }
    }
}

pub fn validate_protocol_requirements(
    compliance_profile_id: Option<&str>,
    format: CredentialFormat,
    vct: Option<&str>,
    doctype: Option<&str>,
) -> Result<(), CredentialTemplateError> {
    if compliance_profile_id.is_none_or(|value| value.trim().is_empty()) {
        return Err(CredentialTemplateError::MissingComplianceProfile);
    }
    match format {
        CredentialFormat::SdJwtVc => {
            let value = vct
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(CredentialTemplateError::MissingVct)?;
            let scheme = uri_scheme(value).ok_or(CredentialTemplateError::VctMustBeAbsolute)?;
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
                let parsed = url::Url::parse(value)
                    .map_err(|_| CredentialTemplateError::VctMustBeAbsolute)?;
                if parsed.host_str() == Some("marty.example") {
                    return Err(CredentialTemplateError::PlaceholderVctOrigin);
                }
            }
        }
        CredentialFormat::Mdoc if doctype.is_none_or(|value| value.trim().is_empty()) => {
            return Err(CredentialTemplateError::MissingDoctype);
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    Development,
    Test,
    Beta,
    Production,
}

pub fn validate_wallet_inner_uri(
    value: &str,
    environment: RuntimeEnvironment,
) -> Result<String, CredentialTemplateError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CredentialTemplateError::MissingInnerUri);
    }
    let scheme = uri_scheme(value).ok_or(CredentialTemplateError::DisallowedInnerUriScheme)?;
    let allowed = matches!(
        scheme.to_ascii_lowercase().as_str(),
        "https" | "openid-credential-offer" | "openid4vp" | "haip-vci" | "haip-vp"
    ) || (scheme.eq_ignore_ascii_case("http")
        && matches!(
            environment,
            RuntimeEnvironment::Development | RuntimeEnvironment::Test
        ));
    if !allowed {
        return Err(CredentialTemplateError::DisallowedInnerUriScheme);
    }
    if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        let authority = value
            .split_once("://")
            .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
            .unwrap_or_default();
        if authority.is_empty() || url::Url::parse(value).is_err() {
            return Err(CredentialTemplateError::InnerUriMissingHost);
        }
    }
    Ok(value.to_owned())
}

pub fn render_wallet_open_uri(
    template: &str,
    inner_uri: &str,
    wallet_id: &str,
    platform: Option<&str>,
) -> Result<String, CredentialTemplateError> {
    if template.is_empty() {
        return Ok(inner_uri.to_owned());
    }
    let (offer_parameter, offer_value) = credential_offer_parts(inner_uri);
    let template = if offer_parameter == "credential_offer" {
        Regex::new(
            r"credential_offer_uri=(\{(?:offer_uri|offer|credential_offer_uri)(?:_encoded)?\})",
        )
        .map_err(|_| CredentialTemplateError::InvalidWalletTemplate)?
        .replace_all(template, "credential_offer=$1")
        .into_owned()
    } else {
        template.to_owned()
    };
    let request_uri = query_value(inner_uri, &["request_uri"]);
    let replacements = BTreeMap::from([
        ("credential_offer_param", offer_parameter.to_owned()),
        ("credential_offer_uri", offer_value.clone()),
        ("credential_offer_uri_encoded", percent_encode(&offer_value)),
        ("inner_uri", inner_uri.to_owned()),
        ("inner_uri_encoded", percent_encode(inner_uri)),
        ("offer", offer_value.clone()),
        ("offer_encoded", percent_encode(&offer_value)),
        ("offer_uri", offer_value.clone()),
        ("offer_uri_encoded", percent_encode(&offer_value)),
        ("platform", platform.unwrap_or_default().to_owned()),
        ("request_uri", request_uri.clone()),
        ("request_uri_encoded", percent_encode(&request_uri)),
        ("uri", inner_uri.to_owned()),
        ("uri_encoded", percent_encode(inner_uri)),
        ("wallet_id", wallet_id.to_owned()),
    ]);
    let placeholder = Regex::new(r"\{([a-zA-Z0-9_]+)\}")
        .map_err(|_| CredentialTemplateError::InvalidWalletTemplate)?;
    Ok(placeholder
        .replace_all(&template, |captures: &regex::Captures<'_>| {
            replacements
                .get(&captures[1])
                .cloned()
                .unwrap_or_else(|| captures[0].to_owned())
        })
        .into_owned())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryDestinationPolicy {
    pub provider: String,
    pub mode: String,
    pub setup_actor: String,
    pub delivery_target: String,
    pub is_system: bool,
    pub organization_id: Option<String>,
}

impl DeliveryDestinationPolicy {
    pub fn validate(&self) -> Result<(), CredentialTemplateError> {
        require_allowed(
            &self.provider,
            &[
                "elevenid_wallet",
                "oid4vci_wallet",
                "didcomm_v2",
                "canvas_credentials",
                "canvas_credentials_backpack",
                "open_badges_backpack",
                "custom",
                "physical_document_bureau",
            ],
            "delivery destination provider",
        )?;
        require_allowed(
            &self.mode,
            &[
                "holder_wallet",
                "learner_backpack",
                "organization_mirror",
                "direct_delivery",
                "physical_document",
            ],
            "delivery destination mode",
        )?;
        require_allowed(
            &self.setup_actor,
            &["learner", "org_admin", "system"],
            "delivery destination setup actor",
        )?;
        require_allowed(
            &self.delivery_target,
            &[
                "wallet",
                "didcomm_v2",
                "canvas_credentials",
                "external_api",
                "webhook",
                "physical_document",
            ],
            "delivery target",
        )?;
        if self.mode == "organization_mirror" && self.setup_actor != "org_admin" {
            return Err(CredentialTemplateError::OrganizationMirrorRequiresAdmin);
        }
        if !self.is_system
            && self
                .organization_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(CredentialTemplateError::MissingDestinationOrganization);
        }
        Ok(())
    }
}

fn require_allowed(
    value: &str,
    allowed: &[&str],
    field: &str,
) -> Result<(), CredentialTemplateError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(CredentialTemplateError::InvalidConfiguration(format!(
            "unsupported {field}: {value}"
        )))
    }
}

fn uri_scheme(value: &str) -> Option<&str> {
    let (scheme, _) = value.split_once(':')?;
    (!scheme.is_empty()
        && scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || (index > 0 && matches!(byte, b'0'..=b'9' | b'+' | b'-' | b'.'))
        }))
    .then_some(scheme)
}

fn query_pairs(uri: &str) -> BTreeMap<String, Vec<String>> {
    let query = uri
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        values
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    values
}

fn query_value(uri: &str, keys: &[&str]) -> String {
    let query = query_pairs(uri);
    for key in keys {
        if let Some(value) = query
            .get(*key)
            .and_then(|values| values.first())
            .filter(|value| !value.is_empty())
        {
            return value.clone();
        }
    }
    uri.to_owned()
}

fn credential_offer_parts(uri: &str) -> (&'static str, String) {
    let query = query_pairs(uri);
    for key in ["credential_offer_uri", "credential_offer"] {
        if let Some(value) = query
            .get(key)
            .and_then(|values| values.first())
            .filter(|value| !value.is_empty())
        {
            return (key, value.clone());
        }
    }
    ("credential_offer_uri", uri.to_owned())
}

fn percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialTemplateError {
    #[error("invalid credential format: {0}")]
    InvalidFormat(String),
    #[error("invalid issuance protocol: {0}")]
    InvalidIssuanceProtocol(String),
    #[error("compliance_profile_id is required")]
    MissingComplianceProfile,
    #[error("vct is required for SD-JWT VC")]
    MissingVct,
    #[error("vct must be an absolute URI")]
    VctMustBeAbsolute,
    #[error("the placeholder marty.example VCT origin is forbidden")]
    PlaceholderVctOrigin,
    #[error("doctype is required for mdoc")]
    MissingDoctype,
    #[error("inner_uri is required")]
    MissingInnerUri,
    #[error("inner_uri scheme is not allowed")]
    DisallowedInnerUriScheme,
    #[error("inner_uri must include a host")]
    InnerUriMissingHost,
    #[error("wallet routing template is invalid")]
    InvalidWalletTemplate,
    #[error("organization_mirror destinations require an organization administrator")]
    OrganizationMirrorRequiresAdmin,
    #[error("organization_id is required for organization delivery destinations")]
    MissingDestinationOrganization,
    #[error("invalid credential-template configuration: {0}")]
    InvalidConfiguration(String),
    #[error("credential_type must be PascalCase or reverse-domain notation: {0}")]
    InvalidCredentialType(String),
    #[error("claims must contain at least one claim definition")]
    MissingClaims,
    #[error("claim names must be unique")]
    DuplicateClaimNames,
    #[error("claim {0} cannot derive from itself")]
    SelfDerivedClaim(String),
    #[error("claim {claim} derives from unknown claim {source_claim}")]
    UnknownDerivedClaim { claim: String, source_claim: String },
    #[error("only draft templates can be modified")]
    TemplateNotDraft,
    #[error("only draft templates can be deleted")]
    TemplateNotDeletable,
    #[error("invalid validity rules: {0}")]
    InvalidValidityRules(String),
}
