//! Public-only HTTP-01 publication contract shared by the installer and responder.
//! No sockets, filesystem access, private key material or service runtime belong here.

use crate::origin::PublicOrigin;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SNAPSHOT_BASENAME: &str = "active.json";
pub const SNAPSHOT_SCHEMA: &str = "elevenid.acme-http01/v1";
pub const MAX_SNAPSHOT_BYTES: u64 = 4096;
pub const MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_CHALLENGES: usize = 2;
const MIN_TOKEN_LENGTH: usize = 22;
const MAX_TOKEN_LENGTH: usize = 256;
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

pub fn valid_token(token: &str) -> bool {
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

    pub fn identifier_for_authority(&self, authority: &str) -> Option<&str> {
        self.identifiers
            .iter()
            .find(|value| {
                authority == value.authority
                    || authority.strip_suffix(":80") == Some(value.authority.as_str())
            })
            .map(|value| value.identifier.as_str())
    }
}
