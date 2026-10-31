//! Canonical public HTTPS origins shared by installer, routing and TLS owners.
//! This is an authority contract, not a general URL parser. It never resolves
//! DNS, changes a listener, or treats a host name as proof of reachability.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const REFUSED: &str = "public origin must be a canonical HTTPS authority without a path, credentials, query or fragment";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicOrigin {
    value: String,
    authority: String,
    host: String,
    port: u16,
    address: Option<IpAddr>,
}

impl PublicOrigin {
    pub fn parse(value: &str) -> Result<Self, String> {
        let authority = value.strip_prefix("https://").ok_or(REFUSED)?;
        if !value.is_ascii()
            || value.len() > 320
            || authority.is_empty()
            || authority.bytes().any(|c| {
                c.is_ascii_control() || c.is_ascii_whitespace() || b"/?#@%\\'\"".contains(&c)
            })
        {
            return Err(REFUSED.into());
        }
        let (host, address, raw_port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, suffix) = rest.split_once(']').ok_or(REFUSED)?;
            let address = host.parse::<std::net::Ipv6Addr>().map_err(|_| REFUSED)?;
            if address.to_string() != host || address.to_ipv4_mapped().is_some() {
                return Err(REFUSED.into());
            }
            let port = if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(':').ok_or(REFUSED)?)
            };
            (host, Some(IpAddr::V6(address)), port)
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            let address = host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4);
            if address.is_none() && !dns_name(host) {
                return Err(REFUSED.into());
            }
            (host, address, port)
        };
        if address.is_some_and(|ip| {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        }) {
            return Err(REFUSED.into());
        }
        let port = match raw_port {
            Some(raw) => {
                let port = raw.parse::<u16>().map_err(|_| REFUSED)?;
                if port == 0 || raw != port.to_string() || port == 443 {
                    return Err(REFUSED.into());
                }
                port
            }
            None => 443,
        };
        Ok(Self {
            value: value.into(),
            authority: authority.into(),
            host: host.into(),
            port,
            address,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Certificate/SNI host; IPv6 brackets belong only to the authority.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn dns_name(&self) -> Option<&str> {
        self.address.is_none().then_some(self.host.as_str())
    }

    pub fn ip_address(&self) -> Option<IpAddr> {
        self.address
    }

    pub fn is_loopback(&self) -> bool {
        self.host == "localhost" || self.address.is_some_and(|ip| ip.is_loopback())
    }
}

impl TryFrom<String> for PublicOrigin {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PublicOrigin> for String {
    fn from(value: PublicOrigin) -> Self {
        value.value
    }
}

impl std::fmt::Display for PublicOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host != host.to_ascii_lowercase() {
        return false;
    }
    // URL implementations interpret numeric final labels as IPv4, sometimes
    // accepting octal, hexadecimal, or shortened spellings. Require standard
    // dotted decimal above instead of allowing different downstream identities.
    let last = host.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|c| c.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return false;
    }
    let valid_labels = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    });
    // Use the same host parser as the downstream HTTP clients. ASCII syntax
    // alone admits invalid IDNA A-labels and numeric aliases such as `0x`;
    // neither may reach provisioning with a different or rejected identity.
    valid_labels
        && matches!(url::Host::parse(host), Ok(url::Host::Domain(parsed)) if parsed == host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_authority_and_listener_port_are_independent() {
        let origin = PublicOrigin::parse("https://marty.example.com").unwrap();
        assert_eq!(origin.port(), 443);
        assert_eq!(origin.authority(), "marty.example.com");
        assert_eq!(origin.dns_name(), Some("marty.example.com"));
        assert_eq!(origin.ip_address(), None);
        assert!(!origin.is_loopback());
        let local = PublicOrigin::parse("https://localhost:18443").unwrap();
        assert_eq!(local.port(), 18443);
        assert!(local.is_loopback());
    }

    #[test]
    fn standard_ip_authorities_keep_certificate_identity_separate() {
        let ipv4 = PublicOrigin::parse("https://203.0.113.10:8443").unwrap();
        assert_eq!(ipv4.dns_name(), None);
        assert_eq!(ipv4.ip_address(), Some("203.0.113.10".parse().unwrap()));
        let ipv6 = PublicOrigin::parse("https://[2001:db8::10]").unwrap();
        assert_eq!(ipv6.authority(), "[2001:db8::10]");
        assert_eq!(ipv6.host(), "2001:db8::10");
        assert_eq!(ipv6.port(), 443);
    }

    #[test]
    fn canonical_idna_alabels_keep_the_downstream_host_identity() {
        for host in ["xn--bcher-kva.example", "xn--caf-dma.example"] {
            let value = format!("https://{host}:8443");
            let origin = PublicOrigin::parse(&value).unwrap();
            assert_eq!(origin.as_str(), value);
            assert_eq!(origin.dns_name(), Some(host));
            assert_eq!(url::Url::parse(&value).unwrap().host_str(), Some(host));
        }
    }

    #[test]
    fn rejects_invalid_idna_alabels_and_downstream_numeric_aliases() {
        for value in [
            "https://xn--a.example",
            "https://xn--ab.example",
            "https://0x",
            "https://example.0x",
        ] {
            assert!(PublicOrigin::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rejects_ambiguous_urls_and_configuration_injection() {
        for value in [
            "http://marty.example.com",
            "https://marty.example.com/",
            "https://user@marty.example.com",
            "https://marty.example.com?q=1",
            "https://marty.example.com#fragment",
            "https://marty.example.com:443",
            "https://marty.example.com:08443",
            "https://marty.example.com:+8443",
            "https://marty.example.com:0",
            "https://marty.example.com:65536",
            "https://MARTY.example.com",
            "https://marty.example.com.",
            "https://*.example.com",
            "https://foo_bar.example.com",
            "https://marty.example.com;include",
            "https://marty.example.com\nBAD=x",
            "https://marty.example.com\\anything",
            "https://127.1",
            "https://0177.0.0.1",
            "https://2130706433",
            "https://0x7f000001",
            "https://0.0.0.0",
            "https://[::]",
            "https://[fe80::1%25eth0]",
            "https://[2001:DB8::1]",
            "https://[2001:0db8::1]",
            "https://[::ffff:127.0.0.1]",
            "https://255.255.255.255",
        ] {
            assert!(PublicOrigin::parse(value).is_err(), "accepted {value:?}");
        }
    }
}
