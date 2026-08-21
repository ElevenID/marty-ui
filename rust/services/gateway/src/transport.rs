use std::{collections::BTreeMap, time::Instant};

use async_trait::async_trait;
use mmf_platform::{
    GatewayRequest, GatewayResponse, HttpMethod, PlatformError, ServiceInstance, UpstreamClient,
};

pub struct ReqwestUpstream {
    client: reqwest::Client,
    maximum_response_bytes: usize,
}

impl ReqwestUpstream {
    pub fn new(maximum_response_bytes: usize) -> Result<Self, PlatformError> {
        if maximum_response_bytes == 0 {
            return Err(PlatformError::InvalidConfiguration(
                "maximum response bytes must be nonzero".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|error| PlatformError::ProviderUnavailable(error.to_string()))?;
        Ok(Self {
            client,
            maximum_response_bytes,
        })
    }
}

#[async_trait]
impl UpstreamClient for ReqwestUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let started = Instant::now();
        let raw_url = format!(
            "{}{}",
            instance.endpoint.url().trim_end_matches('/'),
            if request.path.starts_with('/') {
                request.path.clone()
            } else {
                format!("/{}", request.path)
            }
        );
        let mut url = url::Url::parse(&raw_url)
            .map_err(|error| PlatformError::Operation(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            for (key, values) in &request.query {
                for value in values {
                    query.append_pair(key, value);
                }
            }
        }
        let mut builder = self.client.request(method(request.method), url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(map_reqwest_error)?;
        let status_code = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.as_str().to_owned(),
                    value
                        .to_str()
                        .map_err(|error| PlatformError::Operation(error.to_string()))?
                        .to_owned(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PlatformError>>()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            if body.len().saturating_add(chunk.len()) > self.maximum_response_bytes {
                body.resize(self.maximum_response_bytes.saturating_add(1), 0);
                break;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(GatewayResponse {
            status_code,
            headers,
            body: Some(body),
            response_time_ms: Some(
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ),
            upstream_service: Some(instance.service_name.clone()),
        })
    }
}

fn method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Options => reqwest::Method::OPTIONS,
        HttpMethod::Trace => reqwest::Method::TRACE,
        HttpMethod::Connect => reqwest::Method::CONNECT,
    }
}

fn map_reqwest_error(error: reqwest::Error) -> PlatformError {
    if error.is_timeout() {
        PlatformError::UpstreamTimeout(error.to_string())
    } else if error.is_connect() || error.is_request() || error.is_body() {
        PlatformError::UpstreamTransport(error.to_string())
    } else {
        PlatformError::Operation(error.to_string())
    }
}
