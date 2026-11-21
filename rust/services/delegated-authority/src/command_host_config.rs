//! Explicit configuration for the separate lifecycle-command host.
use std::{collections::BTreeMap, fmt, fs, net::SocketAddr};

use uuid::Uuid;

use crate::{
    approval::organization_principal, ApprovalAdapterPin, Authority, AuthorityMode,
    OrganizationApprovalConfiguration,
};

const DATABASE_FIELDS: [&str; 3] = [
    "DELEGATION_COMMAND_DATABASE_URL",
    "DELEGATION_COMMAND_RUNTIME_DATABASE_URL",
    "DELEGATION_COMMAND_ORGANIZATION_DATABASE_URL",
];

#[derive(Clone)]
pub struct CommandHostConfig {
    pub http_addr: SocketAddr,
    pub command_database_url: String,
    pub runtime_database_url: String,
    pub organization_database_url: String,
    pub service_token: String,
    pub configuration: OrganizationApprovalConfiguration,
    pub authority: Authority,
}

impl fmt::Debug for CommandHostConfig {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("CommandHostConfig")
            .field("http_addr", &self.http_addr)
            .field("organization_id", &self.configuration.organization_id())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommandHostConfigError {
    #[error("delegation commands require explicit MARTY_DELEGATION_COMMANDS_ENABLED=true")]
    Disabled,
    #[error("delegation command configuration is missing or invalid: {0}")]
    Invalid(&'static str),
    #[error("delegation command secret file is unreadable or conflicts with an inline value: {0}")]
    SecretFile(&'static str),
}

impl CommandHostConfig {
    pub fn from_env() -> Result<Self, CommandHostConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        for name in DATABASE_FIELDS.into_iter().chain(["GRPC_SERVICE_TOKEN"]) {
            load_secret(&mut values, name)?;
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, CommandHostConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        match values
            .get("MARTY_DELEGATION_COMMANDS_ENABLED")
            .map(String::as_str)
        {
            Some("true") => {}
            None | Some("false") => return Err(CommandHostConfigError::Disabled),
            _ => {
                return Err(CommandHostConfigError::Invalid(
                    "MARTY_DELEGATION_COMMANDS_ENABLED",
                ))
            }
        }
        let http_addr = values
            .get("DELEGATION_COMMAND_HTTP_ADDR")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:8020")
            .parse()
            .map_err(|_| CommandHostConfigError::Invalid("DELEGATION_COMMAND_HTTP_ADDR"))?;
        let id_text = required(&values, "DELEGATION_COMMAND_ORGANIZATION_ID")?;
        let id = Uuid::parse_str(id_text)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == id_text)
            .ok_or(CommandHostConfigError::Invalid(
                "DELEGATION_COMMAND_ORGANIZATION_ID",
            ))?;
        let token = required(&values, "GRPC_SERVICE_TOKEN")?;
        if !(32..=1024).contains(&token.len())
            || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(CommandHostConfigError::Invalid("GRPC_SERVICE_TOKEN"));
        }
        let pin = ApprovalAdapterPin {
            profile: required(&values, "DELEGATION_COMMAND_APPROVAL_PROFILE")?.to_owned(),
            version: required(&values, "DELEGATION_COMMAND_APPROVAL_VERSION")?.to_owned(),
            artifact_digest: required(&values, "DELEGATION_COMMAND_APPROVAL_ARTIFACT_DIGEST")?
                .to_owned(),
        };
        let configuration = OrganizationApprovalConfiguration::new(
            id,
            organization_principal(id),
            pin,
            120,
            seconds(
                &values,
                "DELEGATION_COMMAND_CONFIRMATION_MAX_AGE_SECONDS",
                300,
                300,
            )?,
            seconds(
                &values,
                "DELEGATION_COMMAND_AUTHORITY_VALIDITY_SECONDS",
                15,
                15,
            )?,
        )
        .map_err(|_| CommandHostConfigError::Invalid("DELEGATION_COMMAND_APPROVAL_PROFILE"))?;
        let authority = Authority {
            mode: AuthorityMode::Managed,
            issuer: organization_principal(id),
            status_ref: required(&values, "DELEGATION_COMMAND_STATUS_REF")?.to_owned(),
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        };
        crate::domain::validate_authority(&authority)
            .map_err(|_| CommandHostConfigError::Invalid("DELEGATION_COMMAND_STATUS_REF"))?;
        let status = url::Url::parse(&authority.status_ref)
            .map_err(|_| CommandHostConfigError::Invalid("DELEGATION_COMMAND_STATUS_REF"))?;
        if !status.username().is_empty()
            || status.password().is_some()
            || status.fragment().is_some()
        {
            return Err(CommandHostConfigError::Invalid(
                "DELEGATION_COMMAND_STATUS_REF",
            ));
        }
        Ok(Self {
            http_addr,
            command_database_url: database_url(&values, DATABASE_FIELDS[0])?,
            runtime_database_url: database_url(&values, DATABASE_FIELDS[1])?,
            organization_database_url: database_url(&values, DATABASE_FIELDS[2])?,
            service_token: token.into(),
            configuration,
            authority,
        })
    }
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, CommandHostConfigError> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .ok_or(CommandHostConfigError::Invalid(name))
}
fn database_url(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, CommandHostConfigError> {
    let text = required(values, name)?;
    let url = url::Url::parse(text).map_err(|_| CommandHostConfigError::Invalid(name))?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str().is_none()
        || url.username().is_empty()
        || url.path().trim_matches('/').is_empty()
        || url.fragment().is_some()
    {
        return Err(CommandHostConfigError::Invalid(name));
    }
    Ok(text.into())
}
fn seconds(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: u32,
    max: u32,
) -> Result<u32, CommandHostConfigError> {
    let seconds = values
        .get(name)
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| CommandHostConfigError::Invalid(name))?
        .unwrap_or(default);
    if !(1..=max).contains(&seconds) {
        return Err(CommandHostConfigError::Invalid(name));
    }
    Ok(seconds)
}
fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), CommandHostConfigError> {
    if let Some(path) = values.get(&format!("{name}_FILE")) {
        if values.contains_key(name) {
            return Err(CommandHostConfigError::SecretFile(name));
        }
        let value =
            fs::read_to_string(path).map_err(|_| CommandHostConfigError::SecretFile(name))?;
        values.insert(name.into(), value.trim_end_matches(['\r', '\n']).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("MARTY_DELEGATION_COMMANDS_ENABLED".into(), "true".into()),
            ("GRPC_SERVICE_TOKEN".into(), "s".repeat(32)),
            (
                "DELEGATION_COMMAND_ORGANIZATION_ID".into(),
                "11111111-1111-4111-8111-111111111111".into(),
            ),
            (
                "DELEGATION_COMMAND_APPROVAL_PROFILE".into(),
                "urn:test:approval".into(),
            ),
            ("DELEGATION_COMMAND_APPROVAL_VERSION".into(), "1.0.0".into()),
            (
                "DELEGATION_COMMAND_APPROVAL_ARTIFACT_DIGEST".into(),
                format!("sha256:{}", "a".repeat(64)),
            ),
            (
                "DELEGATION_COMMAND_STATUS_REF".into(),
                "https://issuer.example.invalid/delegations/status".into(),
            ),
        ])
        .into_iter()
        .chain(DATABASE_FIELDS.map(|name| {
            (
                name.into(),
                "postgresql://runtime:synthetic-secret@127.0.0.1/db".into(),
            )
        }))
        .collect()
    }
    #[test]
    fn command_host_is_explicit_and_contains_no_producer_writer_configuration() {
        assert_eq!(
            CommandHostConfig::from_values(BTreeMap::new()).unwrap_err(),
            CommandHostConfigError::Disabled
        );
        let config = CommandHostConfig::from_values(values()).unwrap();
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8020");
        assert!(!format!("{config:?}").contains("synthetic-secret"));
        let mut input = values();
        input.insert(
            "DELEGATION_COMMAND_STATUS_REF".into(),
            "http://issuer.example.invalid/status".into(),
        );
        assert!(CommandHostConfig::from_values(input).is_err());
        for name in [
            "DELEGATION_COMMAND_CONFIRMATION_MAX_AGE_SECONDS",
            "DELEGATION_COMMAND_AUTHORITY_VALIDITY_SECONDS",
        ] {
            let mut input = values();
            input.insert(name.into(), "301".into());
            assert!(CommandHostConfig::from_values(input).is_err());
        }
    }
}
