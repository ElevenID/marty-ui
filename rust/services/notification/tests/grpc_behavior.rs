use marty_notification::{
    grpc::NotificationGrpc,
    proto::{
        notification_service_server::NotificationService, DeleteNotificationRequest,
        GetNotificationRequest, GetUnreadCountRequest, ListNotificationsRequest,
        MarkAllAsReadRequest, MarkAsReadRequest, SendNotificationRequest,
    },
    repository::InMemoryNotificationRepository,
};
use std::sync::Arc;
use tonic::{Code, Request};

fn grpc() -> NotificationGrpc {
    NotificationGrpc::new(Arc::new(InMemoryNotificationRepository::default()))
}

#[tokio::test]
async fn grpc_crud_and_unread_behavior_matches_the_protocol() {
    let service = grpc();
    let sent = service
        .send_notification(Request::new(SendNotificationRequest {
            organization_id: "org-a".into(),
            recipient_id: "user-a".into(),
            recipient_email: "user@example.com".into(),
            notification_type: "email".into(),
            subject: "Hello".into(),
            body: "Body".into(),
            priority: "normal".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(sent.title, "Hello");
    assert!(!sent.read);
    assert_eq!(sent.status, "failed");
    let fetched = service
        .get_notification(Request::new(GetNotificationRequest {
            notification_id: sent.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.id, sent.id);
    let listed = service
        .list_notifications(Request::new(ListNotificationsRequest {
            organization_id: "org-a".into(),
            recipient_id: "user-a".into(),
            limit: 100,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.notifications.len(), 1);
    assert_eq!(
        service
            .get_unread_count(Request::new(GetUnreadCountRequest {
                recipient_id: "user-a".into()
            }))
            .await
            .unwrap()
            .into_inner()
            .count,
        1
    );
    assert!(
        service
            .mark_as_read(Request::new(MarkAsReadRequest {
                notification_id: sent.id.clone()
            }))
            .await
            .unwrap()
            .into_inner()
            .read
    );
    assert_eq!(
        service
            .mark_all_as_read(Request::new(MarkAllAsReadRequest {
                recipient_id: "user-a".into(),
                organization_id: "org-a".into()
            }))
            .await
            .unwrap()
            .into_inner()
            .updated_count,
        0
    );
    assert!(
        service
            .delete_notification(Request::new(DeleteNotificationRequest {
                notification_id: sent.id.clone()
            }))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert_eq!(
        service
            .get_notification(Request::new(GetNotificationRequest {
                notification_id: sent.id
            }))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn grpc_rejects_invalid_status_instead_of_ignoring_it() {
    let error = grpc()
        .list_notifications(Request::new(ListNotificationsRequest {
            status: "unknown".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
}
