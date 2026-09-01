//! Shared bounded HTTP client construction for Canvas provider traffic.

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use reqwest::{redirect::Policy, Client, Response};
use url::Url;

#[derive(Clone)]
pub struct CanvasHttpClientPolicy {
    pub timeout: Duration,
    pub private_origin_allowlist: Vec<String>,
    pub allow_private_networks: bool,
    pub allow_http_localhost: bool,
}

impl std::fmt::Debug for CanvasHttpClientPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasHttpClientPolicy")
            .field("timeout", &self.timeout)
            .field(
                "private_origin_allowlist_count",
                &self.private_origin_allowlist.len(),
            )
            .field("allow_private_networks", &self.allow_private_networks)
            .field("allow_http_localhost", &self.allow_http_localhost)
            .finish()
    }
}

pub async fn client_for_canvas_origin(
    canvas_base_url: &str,
    policy: &CanvasHttpClientPolicy,
) -> Result<(Client, Url), ()> {
    let origin = Url::parse(canvas_base_url).map_err(|_| ())?;
    let host = origin.host_str().ok_or(())?;
    let http_localhost = origin.scheme() == "http"
        && policy.allow_http_localhost
        && matches!(
            host.to_ascii_lowercase().as_str(),
            "localhost" | "127.0.0.1" | "::1"
        );
    if !(origin.scheme() == "https" || http_localhost)
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !(origin.path().is_empty() || origin.path() == "/")
    {
        return Err(());
    }
    let port = origin.port_or_known_default().ok_or(())?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ())?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(());
    }
    let requested_origin = normalized_origin(&origin);
    let exact_origin_allowed = policy
        .private_origin_allowlist
        .iter()
        .filter_map(|candidate| Url::parse(candidate.trim()).ok())
        .filter_map(|candidate| normalized_origin(&candidate))
        .any(|candidate| {
            requested_origin
                .as_ref()
                .is_some_and(|origin| candidate == *origin)
        });
    let private_allowed = policy.allow_private_networks || exact_origin_allowed || http_localhost;
    if !private_allowed && addresses.iter().any(|address| is_private_ip(address.ip())) {
        return Err(());
    }
    let pinned = preferred_address(&addresses).ok_or(())?;
    let client = Client::builder()
        .timeout(policy.timeout)
        .redirect(Policy::none())
        .no_proxy()
        .resolve(host, pinned)
        .build()
        .map_err(|_| ())?;
    Ok((client, origin))
}

fn normalized_origin(url: &Url) -> Option<String> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.path().is_empty() || url.path() == "/")
    {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    match url.port_or_known_default()? {
        443 => Some(format!("https://{host}")),
        port => Some(format!("https://{host}:{port}")),
    }
}

#[must_use]
pub fn canvas_retry_after_seconds(response: &Response) -> Option<u64> {
    let raw = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(seconds.min(86_400));
    }
    let retry_at = httpdate::parse_http_date(raw).ok()?;
    Some(
        retry_at
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_secs()
            .min(86_400),
    )
}

fn preferred_address(addresses: &[SocketAddr]) -> Option<SocketAddr> {
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            let [first, second, third, _] = value.octets();
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_broadcast()
                || value.is_documentation()
                || value.is_multicast()
                || value.is_unspecified()
                || first == 0
                || first >= 240
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 198 && (18..=19).contains(&second))
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            value.is_loopback()
                || value.is_unspecified()
                || value.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || value
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_private_ip(IpAddr::V4(mapped)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn dns_pin_policy_rejects_private_special_and_documentation_ranges() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "2001:db8::1".parse().expect("documentation IPv6"),
        ] {
            assert!(is_private_ip(ip), "{ip} must fail closed");
        }
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn policy_debug_redacts_private_origins() {
        let policy = CanvasHttpClientPolicy {
            timeout: Duration::from_secs(10),
            private_origin_allowlist: vec!["https://private-sensitive.example".to_owned()],
            allow_private_networks: false,
            allow_http_localhost: false,
        };
        let debug = format!("{policy:?}");
        assert!(debug.contains("private_origin_allowlist_count: 1"));
        assert!(!debug.contains("private-sensitive"));
    }

    #[test]
    fn private_allowlist_normalization_is_exact_and_ignores_invalid_entries() {
        let origin = Url::parse("https://Canvas.Internal.Example.:443/").unwrap();
        assert_eq!(
            normalized_origin(&origin).as_deref(),
            Some("https://canvas.internal.example")
        );
        assert!(
            normalized_origin(&Url::parse("https://user:secret@example.test").unwrap()).is_none()
        );
        assert!(
            normalized_origin(&Url::parse("http://canvas.internal.example").unwrap()).is_none()
        );
    }
}
