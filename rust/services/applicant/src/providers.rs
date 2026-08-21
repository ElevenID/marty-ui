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
use tonic::transport::Channel;
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
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').into(),
            api_key,
        }
    }
}

#[async_trait]
impl TemplateProvider for HttpTemplateProvider {
    async fn get(&self, id: &str) -> Result<ApplicationTemplate, ProviderError> {
        let mut request = self
            .client
            .get(format!("{}/v1/application-templates/{id}", self.base_url));
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
        response
            .error_for_status()
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?
            .json::<ApplicationTemplate>()
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))
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
        let payload = json!({
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
    client: Client,
}

impl GrpcEventPublisher {
    pub fn new(
        channel: Channel,
        notification_url: Option<String>,
        notification_token: Option<String>,
    ) -> Self {
        Self {
            channel,
            notification_url,
            notification_token,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl EventPublisher for GrpcEventPublisher {
    async fn publish(&self, event: &ApplicationEvent) -> Result<(), ProviderError> {
        if event.organization_id.trim().is_empty() {
            return Err(ProviderError::Unavailable(
                "refusing to publish an unscoped applicant event".into(),
            ));
        }
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
        let event_id = Uuid::new_v4().to_string();
        let wire = DomainEvent {
            event_id: event_id.clone(),
            event_type: event.event_type.clone(),
            aggregate_id: event.aggregate_id.clone(),
            aggregate_type: event.aggregate_type.clone(),
            organization_id: event.organization_id.clone(),
            data,
            timestamp: event.timestamp.to_rfc3339(),
            correlation_id: String::new(),
        };
        let response = EventStreamServiceClient::new(self.channel.clone())
            .publish(PublishEventRequest { event: Some(wire) })
            .await
            .map_err(|error| ProviderError::Unavailable(error.to_string()))?
            .into_inner();
        if !response.success {
            return Err(ProviderError::Unavailable(
                "event stream rejected applicant event".into(),
            ));
        }
        if let (Some(url), Some(token)) = (&self.notification_url, &self.notification_token) {
            let _ = self
                .client
                .post(url)
                .header("x-service-token", token)
                .header("x-marty-event-producer", "applicant")
                .json(&json!({
                    "event_id": event_id,
                    "event_type": event.event_type,
                    "aggregate_id": event.aggregate_id,
                    "aggregate_type": event.aggregate_type,
                    "organization_id": event.organization_id,
                    "data": event.data,
                    "timestamp": event.timestamp.to_rfc3339(),
                }))
                .send()
                .await;
        }
        Ok(())
    }
}
