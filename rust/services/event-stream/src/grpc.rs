use crate::{
    bus::{EventBus, SubscriptionFilter},
    proto::{
        event_stream_service_server::EventStreamService, DomainEvent, EventSubscription,
        HealthCheckRequest, HealthCheckResponse, PublishEventRequest, PublishEventResponse,
    },
};
use futures_core::Stream;
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use std::{collections::HashSet, pin::Pin};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct EventStreamGrpc {
    bus: EventBus,
    authenticator: ServiceTokenAuthenticator,
}

impl EventStreamGrpc {
    pub fn new(
        bus: EventBus,
        service_token: Option<String>,
        required: bool,
    ) -> Result<Self, SecurityError> {
        Ok(Self {
            bus,
            authenticator: ServiceTokenAuthenticator::new(service_token, required)?,
        })
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let token = request
            .metadata()
            .get("x-service-token")
            .and_then(|value| value.to_str().ok());
        self.authenticator
            .authenticate(token)
            .map_err(|_| Status::unauthenticated("EVENT_STREAM.SERVICE_TOKEN_REQUIRED"))
    }
}

#[tonic::async_trait]
impl EventStreamService for EventStreamGrpc {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<DomainEvent, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        request: Request<EventSubscription>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        self.authenticate(&request)?;
        let request = request.into_inner();
        let subscription = self
            .bus
            .subscribe(
                request.subscriber_id,
                SubscriptionFilter {
                    event_types: request.event_types.into_iter().collect::<HashSet<_>>(),
                    organization_id: request.organization_id,
                    aggregate_type: request.aggregate_type,
                },
            )
            .await;
        let stream = subscription.into_stream().map(Ok);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn publish(
        &self,
        request: Request<PublishEventRequest>,
    ) -> Result<Response<PublishEventResponse>, Status> {
        self.authenticate(&request)?;
        // Python protobuf message fields expose an empty default message when
        // omitted. Preserve that wire behavior and let the bus add ID/time.
        let event = request.into_inner().event.unwrap_or_default();
        let subscribers_notified = self.bus.publish(event).await;
        Ok(Response::new(PublishEventResponse {
            success: true,
            subscribers_notified,
        }))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.authenticate(&request)?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::AsciiMetadataValue;

    #[tokio::test]
    async fn deployed_service_requires_a_valid_token_for_every_rpc() {
        let service = EventStreamGrpc::new(EventBus::default(), Some("s".repeat(32)), true)
            .expect("valid service token");
        assert_eq!(
            service
                .health_check(Request::new(HealthCheckRequest {}))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            service
                .publish(Request::new(PublishEventRequest { event: None }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            service
                .subscribe(Request::new(EventSubscription::default()))
                .await
                .err()
                .expect("missing token must be rejected")
                .code(),
            tonic::Code::Unauthenticated
        );
        let mut request = Request::new(HealthCheckRequest {});
        request.metadata_mut().insert(
            "x-service-token",
            AsciiMetadataValue::try_from("s".repeat(32)).unwrap(),
        );
        assert_eq!(
            service
                .health_check(request)
                .await
                .unwrap()
                .into_inner()
                .status,
            "serving"
        );
    }
}
