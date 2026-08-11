use crate::{
    bus::{EventBus, SubscriptionFilter},
    proto::{
        event_stream_service_server::EventStreamService, DomainEvent, EventSubscription,
        HealthCheckRequest, HealthCheckResponse, PublishEventRequest, PublishEventResponse,
    },
};
use futures_core::Stream;
use std::{collections::HashSet, pin::Pin};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct EventStreamGrpc {
    bus: EventBus,
}

impl EventStreamGrpc {
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
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
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}
