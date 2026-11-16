use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::PortError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcClientAuthMethod {
    None,
    ClientSecretPost,
    ClientSecretBasic,
}

impl OidcClientAuthMethod {
    pub fn parse(value: &str) -> Result<Self, PortError> {
        match value {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            _ => Err(configuration(
                "OIDC token authentication must be none, client_secret_post or client_secret_basic",
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OidcUserInfoMode {
    #[default]
    Disabled,
    Fallback,
}

impl OidcUserInfoMode {
    pub fn parse(value: &str) -> Result<Self, PortError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "fallback" => Ok(Self::Fallback),
            _ => Err(configuration(
                "OIDC UserInfo mode must be disabled or fallback",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OidcPrompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl OidcPrompt {
    pub fn parse_list(value: &str) -> Result<Vec<Self>, PortError> {
        if value.len() > 64 || value.chars().any(|c| c.is_control()) {
            return Err(configuration("OIDC prompt policy is invalid"));
        }
        let result = value
            .split(' ')
            .filter(|value| !value.is_empty())
            .map(|prompt| match prompt {
                "none" => Ok(Self::None),
                "login" => Ok(Self::Login),
                "consent" => Ok(Self::Consent),
                "select_account" => Ok(Self::SelectAccount),
                _ => Err(configuration(
                    "OIDC prompt must contain only none, login, consent or select_account",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::validate_list(&result)?;
        Ok(result)
    }

    pub fn validate_list(values: &[Self]) -> Result<(), PortError> {
        let unique = values.iter().collect::<HashSet<_>>();
        if unique.len() != values.len() || (values.contains(&Self::None) && values.len() != 1) {
            return Err(configuration(
                "OIDC prompts must be unique and none cannot be combined",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMaxAge {
    Seconds(u64),
    Omit,
}

impl Default for OidcMaxAge {
    fn default() -> Self {
        Self::Seconds(0)
    }
}

impl OidcMaxAge {
    pub fn parse(value: &str) -> Result<Self, PortError> {
        if value == "omit" {
            return Ok(Self::Omit);
        }
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(configuration(
                "OIDC max age must be 0..86400 seconds or omit",
            ));
        }
        let seconds = value
            .parse::<u64>()
            .map_err(|_| configuration("OIDC max age is invalid"))?;
        if seconds > 86_400 {
            return Err(configuration("OIDC max age must not exceed 86400 seconds"));
        }
        Ok(Self::Seconds(seconds))
    }

    #[must_use]
    pub const fn seconds(self) -> Option<u64> {
        match self {
            Self::Seconds(seconds) => Some(seconds),
            Self::Omit => None,
        }
    }
}

/// Deliberately public, non-secret information for login and account screens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OidcProviderCapabilities {
    pub provider_mode: &'static str,
    pub provider_name: String,
    pub registration_supported: bool,
    pub account_url: Option<String>,
    pub recovery_url: Option<String>,
    pub passkey_enrollment_supported: bool,
    pub provider_logout_supported: bool,
}

/// Retained with one-time PKCE state so callbacks cannot silently use changed
/// authorization policy. States created before this field existed remain valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcAuthenticationFreshness {
    pub max_age_seconds: u64,
    pub leeway_seconds: u64,
}

impl OidcAuthenticationFreshness {
    pub fn validate(
        &self,
        claims: &Value,
        authorization_started_at: i64,
        now: i64,
    ) -> Result<(), PortError> {
        let invalid = || {
            PortError::new(
                "oidc_authentication_too_old",
                "OIDC authentication freshness was not established",
            )
        };
        if self.max_age_seconds > 86_400 || self.leeway_seconds > 300 {
            return Err(invalid());
        }
        let auth_time = claims
            .get("auth_time")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?;
        let issued_at = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?;
        let leeway = self.leeway_seconds as i64;
        // Compare against the authorization start, not the callback time: a
        // legitimate user may spend several minutes completing login/consent.
        if auth_time <= 0
            || auth_time > now.saturating_add(leeway)
            || auth_time > issued_at.saturating_add(leeway)
            || auth_time
                < authorization_started_at
                    .saturating_sub(self.max_age_seconds as i64)
                    .saturating_sub(leeway)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Accept bounded language tags, never arbitrary authorization parameters.
pub fn validate_ui_locales(value: &str) -> Result<String, PortError> {
    let invalid = || {
        PortError::new(
            "invalid_oidc_locale",
            "OIDC locales must be a bounded list of language tags",
        )
    };
    if value.is_empty() || value.len() > 128 || value.trim() != value {
        return Err(invalid());
    }
    let tags = value.split(' ').collect::<Vec<_>>();
    if tags.len() > 8 {
        return Err(invalid());
    }
    let mut seen = HashSet::new();
    for tag in &tags {
        let mut subtags = tag.split('-');
        let language = subtags.next().ok_or_else(invalid)?;
        if tag.len() > 35
            || !(2..=8).contains(&language.len())
            || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
            || subtags.any(|subtag| {
                subtag.is_empty()
                    || subtag.len() > 8
                    || !subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
            || !seen.insert(tag.to_ascii_lowercase())
        {
            return Err(invalid());
        }
    }
    Ok(tags.join(" "))
}

fn configuration(message: &str) -> PortError {
    PortError::new("invalid_oidc_configuration", message)
}
