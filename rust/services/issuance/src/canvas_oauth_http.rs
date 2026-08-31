use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde_json::Value;

use crate::{
    canvas_oauth::{CanvasOAuthProvider, CanvasOAuthProviderError, CanvasOAuthTokenBundle},
    canvas_provider_http::{
        canvas_retry_after_seconds, client_for_canvas_origin, CanvasHttpClientPolicy,
    },
};

const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct HttpCanvasOAuthProvider {
    policy: CanvasHttpClientPolicy,
}

impl std::fmt::Debug for HttpCanvasOAuthProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasOAuthProvider")
            .field("policy", &self.policy)
            .finish()
    }
}

impl HttpCanvasOAuthProvider {
    #[must_use]
    pub fn new(
        timeout: Duration,
        private_origin_allowlist: Vec<String>,
        allow_private_networks: bool,
    ) -> Self {
        Self {
            policy: CanvasHttpClientPolicy {
                timeout,
                private_origin_allowlist,
                allow_private_networks,
                allow_http_localhost: false,
            },
        }
    }

    #[must_use]
    pub fn new_with_policy(
        timeout: Duration,
        private_origin_allowlist: Vec<String>,
        allow_private_networks: bool,
        allow_http_localhost: bool,
    ) -> Self {
        Self {
            policy: CanvasHttpClientPolicy {
                timeout,
                private_origin_allowlist,
                allow_private_networks,
                allow_http_localhost,
            },
        }
    }

    async fn client_for_origin(
        &self,
        canvas_base_url: &str,
    ) -> Result<(reqwest::Client, url::Url), CanvasOAuthProviderError> {
        client_for_canvas_origin(canvas_base_url, &self.policy)
            .await
            .map_err(|()| provider_error(None))
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
            .map_err(transport_error)?;
        if response.status().is_redirection() {
            return Err(provider_error(None));
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(provider_error(canvas_retry_after_seconds(&response)));
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

    async fn refresh(
        &self,
        canvas_base_url: &str,
        client_id: &str,
        client_secret: &str,
        refresh_token: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        let (client, origin) = self.client_for_origin(canvas_base_url).await?;
        let endpoint = origin
            .join("/login/oauth2/token")
            .map_err(|_| provider_error(None))?;
        let response = client
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(transport_error)?;
        if response.status().is_redirection() {
            return Err(provider_error(None));
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(provider_error(canvas_retry_after_seconds(&response)));
        }
        if matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(CanvasOAuthProviderError::RefreshRejected);
        }
        if !response.status().is_success() {
            return Err(provider_error(None));
        }
        let payload = limited_json(response).await?;
        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| provider_error(None))?
            .to_owned();
        let rotated_refresh_token = payload
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| Some(refresh_token.to_owned()));
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
            refresh_token: rotated_refresh_token,
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
            .map_err(transport_error)?;
        if response.status().is_redirection() {
            return Err(provider_error(None));
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(provider_error(canvas_retry_after_seconds(&response)));
        }
        if matches!(
            response.status(),
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
        ) {
            Ok(())
        } else {
            Err(CanvasOAuthProviderError::RevocationRejected)
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
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if body.len().saturating_add(chunk.len()) > TOKEN_RESPONSE_MAX_BYTES {
            return Err(provider_error(None));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| provider_error(None))
}

fn provider_error(retry_after_seconds: Option<u64>) -> CanvasOAuthProviderError {
    CanvasOAuthProviderError::Failed {
        retry_after_seconds,
    }
}

fn transport_error(error: reqwest::Error) -> CanvasOAuthProviderError {
    if error.is_timeout() {
        CanvasOAuthProviderError::Timeout
    } else {
        provider_error(None)
    }
}

#[cfg(test)]
mod tests {
    use super::HttpCanvasOAuthProvider;

    #[test]
    fn provider_debug_output_does_not_disclose_private_origins() {
        let provider = HttpCanvasOAuthProvider::new(
            std::time::Duration::from_secs(15),
            vec!["https://private-origin-sensitive.example".to_owned()],
            false,
        );
        let debug = format!("{provider:?}");
        assert!(debug.contains("private_origin_allowlist_count: 1"));
        assert!(!debug.contains("private-origin-sensitive"));
    }
}
