use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use mmf_platform::{
    EndpointProtocol, HealthStatus, InMemoryRegistry, PlatformError, ServiceEndpoint,
    ServiceInstance, ServiceQuery, ServiceRegistry,
};
use tokio::sync::RwLock;
use url::Url;

pub struct StaticServiceRegistry {
    inner: Arc<RwLock<InMemoryRegistry>>,
}

impl StaticServiceRegistry {
    pub fn from_urls(urls: &BTreeMap<String, String>) -> Result<Self, PlatformError> {
        let mut registry = InMemoryRegistry::default();
        for (service, raw_url) in urls {
            let endpoint = endpoint(raw_url)?;
            let mut instance = ServiceInstance::new(service, endpoint, 0)?;
            instance.instance_id = format!("{service}-static");
            instance.update_health(HealthStatus::Healthy, 0);
            registry.register(instance)?;
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(registry)),
        })
    }
}

#[async_trait]
impl ServiceRegistry for StaticServiceRegistry {
    async fn register(&self, instance: &ServiceInstance) -> Result<(), PlatformError> {
        self.inner.write().await.register(instance.clone())
    }

    async fn deregister(&self, service: &str, instance_id: &str) -> Result<bool, PlatformError> {
        Ok(self.inner.write().await.deregister(service, instance_id))
    }

    async fn discover(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>, PlatformError> {
        Ok(self.inner.read().await.discover(query))
    }

    async fn heartbeat(
        &self,
        service: &str,
        instance_id: &str,
        now_ms: u64,
    ) -> Result<(), PlatformError> {
        let query = ServiceQuery {
            service_name: service.into(),
            ..ServiceQuery::default()
        };
        let mut found = self.inner.read().await.discover(&query);
        let instance = found
            .iter_mut()
            .find(|instance| instance.instance_id == instance_id)
            .ok_or_else(|| PlatformError::ServiceNotFound(instance_id.into()))?;
        instance.last_seen_ms = now_ms;
        self.inner.write().await.deregister(service, instance_id);
        self.inner.write().await.register(instance.clone())
    }

    async fn healthy(&self) -> Result<bool, PlatformError> {
        Ok(true)
    }
}

fn endpoint(raw_url: &str) -> Result<ServiceEndpoint, PlatformError> {
    let url = Url::parse(raw_url)
        .map_err(|error| PlatformError::InvalidConfiguration(error.to_string()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PlatformError::InvalidConfiguration(
            "service URLs must not contain credentials, query strings, or fragments".into(),
        ));
    }
    let protocol = match url.scheme() {
        "http" => EndpointProtocol::Http,
        "https" => EndpointProtocol::Https,
        _ => {
            return Err(PlatformError::InvalidConfiguration(
                "gateway upstreams must use HTTP or HTTPS".into(),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| PlatformError::InvalidConfiguration("service URL requires a host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| PlatformError::InvalidConfiguration("service URL requires a port".into()))?;
    Ok(ServiceEndpoint {
        host: host.into(),
        port,
        protocol,
        path: url.path().trim_end_matches('/').into(),
        verify_tls: true,
        connect_timeout_ms: 5_000,
        read_timeout_ms: 30_000,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn service_urls_become_healthy_mmf_instances() {
        let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
            ("auth".into(), "http://auth:8001".into()),
            ("issuance".into(), "https://issuance.example/base/".into()),
        ]))
        .expect("registry");
        let found = registry
            .discover(&ServiceQuery {
                service_name: "issuance".into(),
                healthy_only: true,
                ..ServiceQuery::default()
            })
            .await
            .expect("discovery");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].endpoint.url(), "https://issuance.example:443/base");
    }

    #[test]
    fn unsafe_or_unsupported_service_urls_fail_closed() {
        for value in [
            "http://user:secret@auth:8001",
            "http://auth:8001?token=secret",
            "ftp://auth.example/service",
        ] {
            assert!(StaticServiceRegistry::from_urls(&BTreeMap::from([(
                "auth".into(),
                value.into(),
            )]))
            .is_err());
        }
    }
}
