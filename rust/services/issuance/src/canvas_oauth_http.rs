use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde_json::Value;
use url::Url;

use crate::canvas_oauth::{CanvasOAuthProvider, CanvasOAuthProviderError, CanvasOAuthTokenBundle};

const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct HttpCanvasOAuthProvider {
    timeout: Duration,
    private_origin_allowlist: Vec<String>,
    allow_private_networks: bool,
}

impl HttpCanvasOAuthProvider {
    #[must_use]
    pub fn new(
        timeout: Duration,
        private_origin_allowlist: Vec<String>,
        allow_private_networks: bool,
    ) -> Self {
        Self {
            timeout,
            private_origin_allowlist,
            allow_private_networks,
        }
    }

    async fn client_for_origin(
        &self,
        canvas_base_url: &str,
    ) -> Result<(Client, Url), CanvasOAuthProviderError> {
        let origin = Url::parse(canvas_base_url).map_err(|_| provider_error(None))?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !(origin.path().is_empty() || origin.path() == "/")
        {
            return Err(provider_error(None));
        }
        let host = origin.host_str().ok_or_else(|| provider_error(None))?;
        let port = origin
            .port_or_known_default()
            .ok_or_else(|| provider_error(None))?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| provider_error(None))?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(provider_error(None));
        }
        let allowed_private = self.allow_private_networks
            || self.private_origin_allowlist.iter().any(|candidate| {
                candidate.trim().trim_end_matches('/')
                    == canvas_base_url.trim().trim_end_matches('/')
            });
        if !allowed_private && addresses.iter().any(|address| is_private_ip(address.ip())) {
            return Err(provider_error(None));
        }
        let pinned = preferred_address(&addresses).ok_or_else(|| provider_error(None))?;
        let client = Client::builder()
            .timeout(self.timeout)
            .redirect(Policy::none())
            .no_proxy()
            .resolve(host, pinned)
            .build()
            .map_err(|_| provider_error(None))?;
        Ok((client, origin))
    }
}

#[async_trait]
impl CanvasOAuthProvider for HttpCanvasOAuthProvider {
    async fn exchange(
        &self,
        canvas_base_url: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        let (client, origin) = self.client_for_origin(canvas_base_url).await?;
        let endpoint = origin
            .join("/login/oauth2/token")
            .map_err(|_| provider_error(None))?;
        let response = client
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("code", code),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|_| provider_error(None))?;
        if response.status().is_redirection() {
            return Err(provider_error(None));
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(provider_error(retry_after(&response)));
        }
        if matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) || !response.status().is_success()
        {
            return Err(provider_error(None));
        }
        let payload = limited_json(response).await?;
        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| provider_error(None))?
            .to_owned();
        let refresh_token = payload
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let expires_in_seconds = payload.get("expires_in").and_then(|value| {
            value.as_i64().or_else(|| {
                value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .map(|value| value as i64)
            })
        });
        Ok(CanvasOAuthTokenBundle {
            access_token,
            refresh_token,
            expires_in_seconds,
        })
    }

    async fn revoke(
        &self,
        canvas_base_url: &str,
        access_token: &str,
    ) -> Result<(), CanvasOAuthProviderError> {
        let (client, origin) = self.client_for_origin(canvas_base_url).await?;
        let endpoint = origin
            .join("/login/oauth2/token")
            .map_err(|_| provider_error(None))?;
        let response = client
            .delete(endpoint)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| provider_error(None))?;
        if response.status().is_redirection() {
            return Err(provider_error(None));
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(provider_error(retry_after(&response)));
        }
        if matches!(
            response.status(),
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
        ) {
            Ok(())
        } else {
            Err(provider_error(None))
        }
    }
}

async fn limited_json(mut response: Response) -> Result<Value, CanvasOAuthProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > TOKEN_RESPONSE_MAX_BYTES as u64)
    {
        return Err(provider_error(None));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| provider_error(None))? {
        if body.len().saturating_add(chunk.len()) > TOKEN_RESPONSE_MAX_BYTES {
            return Err(provider_error(None));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| provider_error(None))
}

fn retry_after(response: &Response) -> Option<u64> {
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

fn provider_error(retry_after_seconds: Option<u64>) -> CanvasOAuthProviderError {
    CanvasOAuthProviderError::Failed {
        retry_after_seconds,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_private_ip;

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
}
