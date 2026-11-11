use crate::{
    issuance::IssuanceOffer,
    service::{
        ApplicationEvent, ApplicationTemplate, EventPublisher, FlowProvider, ProviderError,
        TemplateProvider,
    },
    Applicant, Application,
};
use async_trait::async_trait;
use marty_event_stream::proto::{
    event_stream_service_client::EventStreamServiceClient, DomainEvent, PublishEventRequest,
};
use mmf_security::ApplicationEventAuthenticator;
use reqwest::{Client, StatusCode};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Request};
use uuid::Uuid;

#[derive(Clone)]
pub struct HttpTemplateProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl HttpTemplateProvider {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("native issuer HTTP client"),
            base_url: base_url.trim_end_matches('/').into(),
            api_key,
        }
    }
}

#[async_trait]
impl TemplateProvider for HttpTemplateProvider {
    async fn validate_offer_lifetime(
        &self,
        organization_id: &str,
        seconds: u64,
    ) -> Result<(), ProviderError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Echo {
            organization_id: String,
            offer_ttl_seconds: u64,
        }
        if organization_id.trim().is_empty() {
            return Err(ProviderError::Unavailable(
                "issuer lifetime tenant is required".into(),
            ));
        }
        let mut request = self
            .client
            .post(format!(
                "{}/internal/compat/issuance/offer-lifetime/validate",
                self.base_url
            ))
            .header("x-organization-id", organization_id)
            .timeout(std::time::Duration::from_secs(15))
            .json(&json!({"offer_ttl_seconds": seconds}));
        if let Some(key) = &self.api_key {
            request = request.header("x-api-key", key);
        }
        let mut response = request.send().await.map_err(|_| {
            ProviderError::Unavailable("issuer lifetime validation is unavailable".into())
        })?;
        if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
            return Err(ProviderError::InvalidOfferLifetime);
        }
        if response.status() != StatusCode::OK {
            return Err(ProviderError::Unavailable(
                "issuer lifetime validation refused".into(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            ProviderError::Unavailable("issuer lifetime response is unavailable".into())
        })? {
            if body.len() + chunk.len() > 1024 {
                return Err(ProviderError::Unavailable(
                    "issuer lifetime response is invalid".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let echo: Echo = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::Unavailable("issuer lifetime response is invalid".into())
        })?;
        if echo.organization_id != organization_id || echo.offer_ttl_seconds != seconds {
            return Err(ProviderError::Unavailable(
                "issuer lifetime response binding changed".into(),
            ));
        }
        Ok(())
    }

    async fn get(
        &self,
        organization_id: &str,
        id: &str,
    ) -> Result<ApplicationTemplate, ProviderError> {
        if organization_id.trim().is_empty() {
            return Err(ProviderError::Unavailable(
                "template issuer organization is required".into(),
            ));
        }
        let mut request = self
            .client
            .get(format!("{}/v1/application-templates/{id}", self.base_url))
            .header("x-organization-id", organization_id);
        if let Some(api_key) = &self.api_key {
            request = request.header("x-api-key", api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(ProviderError::Unavailable(
                "application template not found".into(),
            ));
        }
        let template = response
            .error_for_status()
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?
            .json::<ApplicationTemplate>()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;
        if template.organization_id != organization_id {
            return Err(ProviderError::Unavailable(
                "template issuer organization mismatch".into(),
            ));
        }
        Ok(template)
    }
}

#[derive(Clone)]
pub struct HttpFlowProvider {
    client: Client,
    base_url: String,
    authenticator: ApplicationEventAuthenticator,
}

impl HttpFlowProvider {
    pub fn new(base_url: String, authenticator: ApplicationEventAuthenticator) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').into(),
            authenticator,
        }
    }
}

#[async_trait]
impl FlowProvider for HttpFlowProvider {
    async fn issue(
        &self,
        application: &Application,
        applicant: &Applicant,
        claims: &Map<String, Value>,
        attempt_id: Uuid,
    ) -> Result<IssuanceOffer, ProviderError> {
        let timestamp = chrono::Utc::now();
        let mut payload = json!({
            "event_type": "application.approved",
            "aggregate_id": application.id,
            "aggregate_type": "application",
            "organization_id": application.organization_id,
            "timestamp": timestamp.to_rfc3339(),
            "data": {
                "applicant_id": applicant.id,
                "application_id": application.id,
                "credential_template_id": application.credential_template_id,
                "email": applicant.email,
                "given_name": applicant.given_name,
                "family_name": applicant.family_name,
                "vetting_level": applicant.vetting_data.get("vetting_level").and_then(Value::as_str).unwrap_or("basic"),
                "application_status": serde_json::to_value(application.status).ok().and_then(|value| value.as_str().map(str::to_ascii_lowercase)).unwrap_or_default(),
                "application_approved_at": application.reviewed_at.unwrap_or(timestamp).to_rfc3339(),
                "triggered_by_event": "application.manual_issue",
                "issuance_attempt_id": attempt_id,
                "claims": claims,
            }
        });
        if let Some(seconds) = application
            .system_data
            .get("active_issuance_attempt")
            .and_then(|value| value.get("offer_ttl_seconds"))
            .and_then(Value::as_u64)
        {
            payload["data"]["offer_ttl_seconds"] = seconds.into();
        }
        let headers = self
            .authenticator
            .sign_new(&payload, timestamp.timestamp())
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;
        let mut request = self.client.post(format!(
            "{}/v1/flows/webhooks/application-approved",
            self.base_url
        ));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request
            .json(&payload)
            .send()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::Unavailable(format!(
                "flow issuance trigger failed with status {status}"
            )));
        }
        let body = response
            .json::<Value>()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;
        let offer = body
            .get("offers")
            .and_then(Value::as_array)
            .and_then(|offers| {
                offers.iter().find(|offer| {
                    offer.get("credential_offer_uri").is_some()
                        || offer.get("credential_offer_uris").is_some()
                })
            })
            .ok_or(ProviderError::NoActiveFlow)?;
        let transaction_id = offer
            .get("credential_offer_transaction_id")
            .or_else(|| offer.get("flow_instance_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Unavailable("flow offer has no transaction id".into()))?;
        Ok(IssuanceOffer {
            id: Some(transaction_id.into()),
            credential_offer_uri: offer
                .get("credential_offer_uri")
                .and_then(Value::as_str)
                .map(str::to_owned),
            credential_offer_uris: string_map(offer.get("credential_offer_uris")),
            credential_offer_labels: string_map(offer.get("credential_offer_labels")),
            expires_at: offer
                .get("expires_at")
                .and_then(Value::as_str)
                .map(str::to_owned),
            status: offer
                .get("issuance_status")
                .and_then(Value::as_str)
                .unwrap_or("pending")
                .into(),
            flow_instance_id: offer
                .get("flow_instance_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            flow_definition_id: offer
                .get("flow_definition_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            source: Some("flow".into()),
        })
    }
}

fn string_map(value: Option<&Value>) -> Map<String, Value> {
    value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct GrpcEventPublisher {
    channel: Channel,
    notification_url: Option<String>,
    notification_token: Option<String>,
    event_stream_token: Option<String>,
    client: Client,
}

impl GrpcEventPublisher {
    pub fn new(
        channel: Channel,
        notification_url: Option<String>,
        notification_token: Option<String>,
        event_stream_token: Option<String>,
    ) -> Self {
        Self {
            channel,
            notification_url,
            notification_token,
            event_stream_token,
            client: Client::new(),
        }
    }
}

fn event_stream_wire(event: &ApplicationEvent, event_id: &str) -> DomainEvent {
    let data = event
        .data
        .as_object()
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    let wire = value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string());
                    (key.clone(), wire)
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    DomainEvent {
        event_id: event_id.into(),
        event_type: event.event_type.clone(),
        aggregate_id: event.aggregate_id.clone(),
        aggregate_type: event.aggregate_type.clone(),
        organization_id: event.organization_id.clone(),
        data,
        timestamp: event.timestamp.to_rfc3339(),
        correlation_id: event.correlation_id.clone(),
    }
}

fn notification_wire(event: &ApplicationEvent, event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "event_type": event.event_type,
        "aggregate_id": event.aggregate_id,
        "aggregate_type": event.aggregate_type,
        "organization_id": event.organization_id,
        "correlation_id": event.correlation_id,
        "data": event.data,
        "timestamp": event.timestamp.to_rfc3339(),
    })
}

#[async_trait]
impl EventPublisher for GrpcEventPublisher {
    async fn publish(&self, event: &ApplicationEvent) -> Result<(), ProviderError> {
        if event.organization_id.trim().is_empty() {
            return Err(ProviderError::Unavailable(
                "refusing to publish an unscoped applicant event".into(),
            ));
        }
        let (Some(url), Some(token)) = (&self.notification_url, &self.notification_token) else {
            return Err(ProviderError::Unavailable(
                "notification event delivery is not configured".into(),
            ));
        };
        self.client
            .post(url)
            .header("x-service-token", token)
            .header("x-marty-event-producer", "applicant")
            .json(&notification_wire(event, &event.event_id))
            .send()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?
            .error_for_status()
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?;

        let wire = event_stream_wire(event, &event.event_id);
        let mut request = Request::new(PublishEventRequest { event: Some(wire) });
        if let Some(token) = &self.event_stream_token {
            let value = AsciiMetadataValue::try_from(token.as_str()).map_err(|_| {
                ProviderError::Unavailable("event-stream service token is invalid".into())
            })?;
            request.metadata_mut().insert("x-service-token", value);
        }
        let response = EventStreamServiceClient::new(self.channel.clone())
            .publish(request)
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?
            .into_inner();
        if !response.success {
            return Err(ProviderError::Unavailable(
                "event stream rejected applicant event".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, Uri},
        routing::get,
        Json, Router,
    };
    use chrono::TimeZone;
    use std::sync::{Arc, Mutex};

    type CapturedRead = Arc<Mutex<Option<(HeaderMap, Uri)>>>;

    async fn application_template(
        State(captured): State<CapturedRead>,
        headers: HeaderMap,
        uri: Uri,
    ) -> Json<Value> {
        *captured.lock().unwrap() = Some((headers, uri));
        Json(json!({
            "id": "application-template-1",
            "organization_id": "org-1",
            "status": "ACTIVE",
            "credential_template_id": "credential-template-1"
        }))
    }

    #[tokio::test]
    async fn template_lookup_uses_configured_native_owner_and_api_key() {
        let captured = CapturedRead::default();
        let app = Router::new()
            .route("/v1/application-templates/{id}", get(application_template))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let api_key = "native-owner-api-key";
        let provider =
            HttpTemplateProvider::new(format!("http://{address}"), Some(api_key.to_owned()));

        let template = provider
            .get("org-1", "application-template-1")
            .await
            .unwrap();
        assert_eq!(template.id, "application-template-1");
        let (headers, uri) = captured.lock().unwrap().take().unwrap();
        assert_eq!(
            uri.path(),
            "/v1/application-templates/application-template-1"
        );
        assert_eq!(headers.get("x-api-key").unwrap(), api_key);
        assert_eq!(headers.get("x-organization-id").unwrap(), "org-1");
        assert!(provider
            .get("foreign-org", "application-template-1")
            .await
            .is_err());
        assert!(provider.get("", "application-template-1").await.is_err());
        server.abort();
    }

    #[test]
    fn approval_correlation_is_identical_on_both_event_boundaries() {
        let event = ApplicationEvent {
            event_id: "event-1".into(),
            event_type: "application.approved".into(),
            aggregate_id: "application-1".into(),
            aggregate_type: "application".into(),
            organization_id: "organization-1".into(),
            correlation_id: "11111111-1111-4111-8111-111111111111".into(),
            timestamp: chrono::Utc
                .with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
                .single()
                .expect("timestamp"),
            data: json!({"application_id": "application-1"}),
        };
        let stream = event_stream_wire(&event, "event-1");
        let notification = notification_wire(&event, "event-1");

        assert_eq!(stream.event_id, "event-1");
        assert_eq!(stream.correlation_id, event.correlation_id);
        assert_eq!(notification["event_id"], "event-1");
        assert_eq!(notification["correlation_id"], event.correlation_id);
    }
    #[tokio::test]
    async fn offer_lifetime_validation_requires_authenticated_exact_issuer_echo() {
        use axum::{
            body::Body,
            response::Response,
            routing::{any, post},
        };
        let redirected: Arc<Mutex<Vec<HeaderMap>>> = Arc::new(Mutex::new(Vec::new()));
        let target_seen = redirected.clone();
        let alternate = Router::new().route(
            "/valid-echo",
            any(move |headers: HeaderMap| {
                let target_seen = target_seen.clone();
                async move {
                    target_seen.lock().unwrap().push(headers);
                    Json(json!({"organization_id":"org-1","offer_ttl_seconds":60}))
                }
            }),
        );
        let alternate_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alternate_url = format!(
            "http://{}/valid-echo",
            alternate_listener.local_addr().unwrap()
        );
        let alternate_server =
            tokio::spawn(async move { axum::serve(alternate_listener, alternate).await.unwrap() });
        // Positive reachability prevents a closed port from masking accidental redirect following.
        let probe = Client::new().get(&alternate_url).send().await.unwrap();
        assert_eq!(
            probe.json::<Value>().await.unwrap(),
            json!({"organization_id":"org-1","offer_ttl_seconds":60})
        );
        assert_eq!(redirected.lock().unwrap().len(), 1);
        redirected.lock().unwrap().clear();
        for (status, body, accepted) in [
            (
                200,
                r#"{"organization_id":"org-1","offer_ttl_seconds":60}"#,
                true,
            ),
            (
                200,
                r#"{"organization_id":"foreign","offer_ttl_seconds":60}"#,
                false,
            ),
            (
                200,
                r#"{"organization_id":"org-1","offer_ttl_seconds":120}"#,
                false,
            ),
            (
                200,
                r#"{"organization_id":"org-1","offer_ttl_seconds":60,"extra":true}"#,
                false,
            ),
            (
                200,
                r#"{"organization_id":"org-1","organization_id":"org-1","offer_ttl_seconds":60}"#,
                false,
            ),
            (200, "not json", false),
            (422, "{}", false),
            (403, "{}", false),
            (503, "{}", false),
            (302, "{}", false),
        ] {
            let captured = Arc::new(Mutex::new(None));
            let sink = captured.clone();
            let redirect_location = alternate_url.clone();
            let app = Router::new().route(
                "/internal/compat/issuance/offer-lifetime/validate",
                post(move |headers: HeaderMap, Json(input): Json<Value>| {
                    let sink = sink.clone();
                    let redirect_location = redirect_location.clone();
                    async move {
                        *sink.lock().unwrap() = Some((headers, input));
                        Response::builder()
                            .status(status)
                            .header("location", redirect_location)
                            .body(Body::from(body))
                            .unwrap()
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let provider = HttpTemplateProvider::new(
                format!("http://{address}"),
                Some("test-native-key".into()),
            );
            assert_eq!(
                provider.validate_offer_lifetime("org-1", 60).await.is_ok(),
                accepted
            );
            let (headers, input) = captured.lock().unwrap().take().unwrap();
            assert_eq!(headers["x-api-key"], "test-native-key");
            assert_eq!(headers["x-organization-id"], "org-1");
            assert_eq!(input, json!({"offer_ttl_seconds":60}));
            assert!(
                redirected.lock().unwrap().is_empty(),
                "issuer validation followed a redirect or forwarded credentials"
            );
            server.abort();
        }
        alternate_server.abort();
    }
}
