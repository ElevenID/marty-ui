use crate::{
    domain::{Notification, NotificationStatus},
    proto::{
        notification_service_server::NotificationService as NotificationServiceGrpc,
        DeleteNotificationRequest, DeleteNotificationResponse, GetNotificationRequest,
        GetUnreadCountRequest, GetUnreadCountResponse, HealthCheckRequest, HealthCheckResponse,
        ListNotificationsRequest, ListNotificationsResponse, MarkAllAsReadRequest,
        MarkAllAsReadResponse, MarkAsReadRequest, NotificationEvent, NotificationResponse,
        SendNotificationRequest, StreamNotificationsRequest,
    },
    service::{NotificationService, SendNotificationRequest as DomainSendRequest, ServiceError},
};
use chrono::Utc;
use futures_core::Stream;
use serde_json::{Map, Value};
use std::{pin::Pin, sync::Arc};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct NotificationGrpc {
    service: NotificationService,
    events: broadcast::Sender<StreamEvent>,
}

#[derive(Clone)]
struct StreamEvent {
    event: NotificationEvent,
    organization_id: Option<String>,
    recipient_id: Option<String>,
}

impl NotificationGrpc {
    pub fn new(repository: Arc<dyn crate::repository::NotificationRepository>) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            service: NotificationService::new(repository),
            events,
        }
    }

    pub fn with_service(service: NotificationService) -> Self {
        let (events, _) = broadcast::channel(256);
        Self { service, events }
    }
}

fn type_name(value: crate::domain::NotificationType) -> String {
    format!("{value:?}").to_ascii_lowercase()
}
fn status_name(value: NotificationStatus) -> String {
    format!("{value:?}").to_ascii_lowercase()
}

fn to_proto(value: &Notification) -> NotificationResponse {
    NotificationResponse {
        id: value.id.clone(),
        notification_type: type_name(value.notification_type),
        status: status_name(value.status),
        read: value.is_read(),
        title: value.subject.clone(),
        message: value.body.clone(),
        severity: value.severity.clone(),
        link: value.link.clone().unwrap_or_default(),
        recipient_email: value.recipient_email.clone().unwrap_or_default(),
        subject: value.subject.clone(),
        created_at: value.created_at.to_rfc3339(),
        delivered_at: value
            .delivered_at
            .map_or_else(String::new, |time| time.to_rfc3339()),
    }
}

fn status(error: ServiceError) -> Status {
    match error {
        ServiceError::Invalid(message) => Status::invalid_argument(message),
        ServiceError::NotFound(kind) => Status::not_found(format!("{kind} not found")),
        ServiceError::Unavailable(message) => Status::unavailable(message),
    }
}

fn parse_status(value: &str) -> Result<Option<NotificationStatus>, Status> {
    if value.is_empty() {
        return Ok(None);
    }
    match value.to_ascii_lowercase().as_str() {
        "pending" => Ok(Some(NotificationStatus::Pending)),
        "sent" => Ok(Some(NotificationStatus::Sent)),
        "delivered" => Ok(Some(NotificationStatus::Delivered)),
        "failed" => Ok(Some(NotificationStatus::Failed)),
        _ => Err(Status::invalid_argument("invalid notification status")),
    }
}

#[tonic::async_trait]
impl NotificationServiceGrpc for NotificationGrpc {
    async fn send_notification(
        &self,
        request: Request<SendNotificationRequest>,
    ) -> Result<Response<NotificationResponse>, Status> {
        let request = request.into_inner();
        let data = Map::from_iter(
            request
                .data
                .into_iter()
                .map(|(key, value)| (key, Value::String(value))),
        );
        let item = self
            .service
            .send(DomainSendRequest {
                organization_id: request.organization_id,
                recipient_id: nonempty(request.recipient_id),
                recipient_email: nonempty(request.recipient_email),
                notification_type: if request.notification_type.is_empty() {
                    "email".into()
                } else {
                    request.notification_type
                },
                template_id: nonempty(request.template_id),
                subject: nonempty(request.subject),
                body: nonempty(request.body),
                severity: if request.severity.is_empty() {
                    "info".into()
                } else {
                    request.severity
                },
                link: nonempty(request.link),
                data,
                priority: if request.priority.is_empty() {
                    "normal".into()
                } else {
                    request.priority
                },
                event_type: "custom".into(),
                ttl_seconds: 86_400,
                ..DomainSendRequest::default()
            })
            .await
            .map_err(status)?;
        let response = to_proto(&item);
        let _ = self.events.send(StreamEvent {
            event: NotificationEvent {
                event_type: "created".into(),
                notification: Some(response.clone()),
                timestamp: Utc::now().to_rfc3339(),
            },
            organization_id: item.organization_id.clone(),
            recipient_id: item.recipient_id.clone(),
        });
        Ok(Response::new(response))
    }

    async fn get_notification(
        &self,
        request: Request<GetNotificationRequest>,
    ) -> Result<Response<NotificationResponse>, Status> {
        let id = request.into_inner().notification_id;
        let item = self
            .service
            .repository()
            .get_notification(&id)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Notification {id} not found")))?;
        Ok(Response::new(to_proto(&item)))
    }

    async fn list_notifications(
        &self,
        request: Request<ListNotificationsRequest>,
    ) -> Result<Response<ListNotificationsResponse>, Status> {
        let request = request.into_inner();
        let mut values = self
            .service
            .repository()
            .list_notifications(
                optional(&request.organization_id),
                optional(&request.recipient_id),
                parse_status(&request.status)?,
            )
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        if request.unread_only {
            values.retain(|item| !item.is_read());
        }
        let total = i32::try_from(values.len()).unwrap_or(i32::MAX);
        let offset = usize::try_from(request.offset.max(0)).unwrap_or_default();
        let limit = usize::try_from(if request.limit <= 0 {
            100
        } else {
            request.limit
        })
        .unwrap_or(100);
        Ok(Response::new(ListNotificationsResponse {
            notifications: values
                .iter()
                .skip(offset)
                .take(limit)
                .map(to_proto)
                .collect(),
            total,
        }))
    }

    async fn get_unread_count(
        &self,
        request: Request<GetUnreadCountRequest>,
    ) -> Result<Response<GetUnreadCountResponse>, Status> {
        let recipient = request.into_inner().recipient_id;
        let values = self
            .service
            .repository()
            .list_notifications(None, optional(&recipient), None)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(Response::new(GetUnreadCountResponse {
            count: i32::try_from(values.iter().filter(|item| !item.is_read()).count())
                .unwrap_or(i32::MAX),
        }))
    }

    async fn mark_as_read(
        &self,
        request: Request<MarkAsReadRequest>,
    ) -> Result<Response<NotificationResponse>, Status> {
        let id = request.into_inner().notification_id;
        let mut item = self
            .service
            .repository()
            .get_notification(&id)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?
            .ok_or_else(|| Status::not_found("Notification not found"))?;
        item.read_at = Some(Utc::now());
        self.service
            .repository()
            .save_notification(item.clone())
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(Response::new(to_proto(&item)))
    }

    async fn mark_all_as_read(
        &self,
        request: Request<MarkAllAsReadRequest>,
    ) -> Result<Response<MarkAllAsReadResponse>, Status> {
        let request = request.into_inner();
        let values = self
            .service
            .repository()
            .list_notifications(
                optional(&request.organization_id),
                optional(&request.recipient_id),
                None,
            )
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let mut count = 0_i32;
        for mut item in values {
            if !item.is_read() {
                item.read_at = Some(Utc::now());
                self.service
                    .repository()
                    .save_notification(item)
                    .await
                    .map_err(|error| Status::unavailable(error.to_string()))?;
                count = count.saturating_add(1);
            }
        }
        Ok(Response::new(MarkAllAsReadResponse {
            updated_count: count,
        }))
    }

    async fn delete_notification(
        &self,
        request: Request<DeleteNotificationRequest>,
    ) -> Result<Response<DeleteNotificationResponse>, Status> {
        if !self
            .service
            .repository()
            .delete_notification(&request.into_inner().notification_id)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?
        {
            return Err(Status::not_found("Notification not found"));
        }
        Ok(Response::new(DeleteNotificationResponse { success: true }))
    }

    type StreamNotificationsStream =
        Pin<Box<dyn Stream<Item = Result<NotificationEvent, Status>> + Send>>;

    async fn stream_notifications(
        &self,
        request: Request<StreamNotificationsRequest>,
    ) -> Result<Response<Self::StreamNotificationsStream>, Status> {
        let filter = request.into_inner();
        let stream =
            BroadcastStream::new(self.events.subscribe()).filter_map(move |event| match event {
                Ok(event)
                    if (filter.organization_id.is_empty()
                        || event.organization_id.as_deref() == Some(&filter.organization_id))
                        && (filter.recipient_id.is_empty()
                            || event.recipient_id.as_deref() == Some(&filter.recipient_id))
                        && event.event.notification.as_ref().is_some_and(|item| {
                            filter.notification_types.is_empty()
                                || filter.notification_types.contains(&item.notification_type)
                        }) =>
                {
                    Some(Ok(event.event))
                }
                Ok(_) | Err(_) => None,
            });
        Ok(Response::new(Box::pin(stream)))
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

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}
