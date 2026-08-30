use crate::{
    domain::{
        DeliveryResult, Notification, NotificationPriority, NotificationStatus, NotificationTarget,
        NotificationTemplate, NotificationType, Subscription, WebhookDelivery, WebhookEndpoint,
    },
    outbox::WebhookOutboxEvent,
    repository::{NotificationRepository, RepositoryError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, PgPool, QueryBuilder, Row};

#[derive(Debug, Clone)]
pub struct PgNotificationRepository {
    pool: PgPool,
}

impl PgNotificationRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn database(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(error.to_string())
}
fn invalid(error: impl ToString) -> RepositoryError {
    RepositoryError::Invalid(error.to_string())
}

fn notification_type(value: &str) -> Result<NotificationType, RepositoryError> {
    match value {
        "email" => Ok(NotificationType::Email),
        "push" => Ok(NotificationType::Push),
        "sms" => Ok(NotificationType::Sms),
        "webhook" => Ok(NotificationType::Webhook),
        _ => Err(invalid("invalid notification type")),
    }
}
fn notification_status(value: &str) -> Result<NotificationStatus, RepositoryError> {
    match value {
        "pending" => Ok(NotificationStatus::Pending),
        "sent" => Ok(NotificationStatus::Sent),
        "delivered" => Ok(NotificationStatus::Delivered),
        "failed" => Ok(NotificationStatus::Failed),
        _ => Err(invalid("invalid notification status")),
    }
}
fn type_name(value: NotificationType) -> &'static str {
    match value {
        NotificationType::Email => "email",
        NotificationType::Push => "push",
        NotificationType::Sms => "sms",
        NotificationType::Webhook => "webhook",
    }
}
fn status_name(value: NotificationStatus) -> &'static str {
    match value {
        NotificationStatus::Pending => "pending",
        NotificationStatus::Sent => "sent",
        NotificationStatus::Delivered => "delivered",
        NotificationStatus::Failed => "failed",
    }
}

fn compose_notification_data(item: &Notification) -> Result<Value, RepositoryError> {
    let mut data = item.data.clone();
    data.insert("__mip".into(), json!({"event_type":item.event_type,"ttl_seconds":item.ttl_seconds,
        "collapse_key":item.collapse_key,"correlation_id":item.correlation_id,"target":item.target,"delivery_results":item.delivery_results}));
    Ok(Value::Object(data))
}

fn row_notification(row: PgRow) -> Result<Notification, RepositoryError> {
    let mut data = row
        .try_get::<Value, _>("data")
        .map_err(database)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    let metadata = data
        .remove("__mip")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let target = metadata
        .get("target")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value::<NotificationTarget>)
        .transpose()
        .map_err(invalid)?;
    let delivery_results = metadata
        .get("delivery_results")
        .cloned()
        .map(serde_json::from_value::<Vec<DeliveryResult>>)
        .transpose()
        .map_err(invalid)?
        .unwrap_or_default();
    let priority =
        NotificationPriority::parse(&row.try_get::<String, _>("priority").map_err(database)?)
            .ok_or_else(|| invalid("invalid priority"))?;
    Ok(Notification {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        recipient_id: row.try_get("recipient_id").map_err(database)?,
        recipient_email: row.try_get("recipient_email").map_err(database)?,
        recipient_phone: row.try_get("recipient_phone").map_err(database)?,
        notification_type: notification_type(
            &row.try_get::<String, _>("notification_type")
                .map_err(database)?,
        )?,
        template_id: row.try_get("template_id").map_err(database)?,
        subject: row.try_get("subject").map_err(database)?,
        body: row.try_get("body").map_err(database)?,
        severity: row.try_get("severity").map_err(database)?,
        link: row.try_get("link").map_err(database)?,
        data,
        status: notification_status(&row.try_get::<String, _>("status").map_err(database)?)?,
        priority,
        event_type: metadata
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("custom")
            .into(),
        ttl_seconds: metadata
            .get("ttl_seconds")
            .and_then(Value::as_i64)
            .unwrap_or(86_400),
        collapse_key: metadata
            .get("collapse_key")
            .and_then(Value::as_str)
            .map(str::to_owned),
        correlation_id: metadata
            .get("correlation_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        target,
        delivery_results,
        attempts: row.try_get("attempts").map_err(database)?,
        last_attempt_at: row.try_get("last_attempt_at").map_err(database)?,
        delivered_at: row.try_get("delivered_at").map_err(database)?,
        error_message: row.try_get("error_message").map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
        scheduled_at: row.try_get("scheduled_at").map_err(database)?,
        read_at: row.try_get("read_at").map_err(database)?,
    })
}

fn row_template(row: PgRow) -> Result<NotificationTemplate, RepositoryError> {
    Ok(NotificationTemplate {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        name: row.try_get("name").map_err(database)?,
        notification_type: notification_type(
            &row.try_get::<String, _>("notification_type")
                .map_err(database)?,
        )?,
        subject_template: row.try_get("subject_template").map_err(database)?,
        body_template: row.try_get("body_template").map_err(database)?,
        active: row.try_get("active").map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
        updated_at: row.try_get("updated_at").map_err(database)?,
    })
}

fn row_subscription(row: PgRow) -> Result<Subscription, RepositoryError> {
    Ok(Subscription {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        name: row.try_get("name").map_err(database)?,
        description: row.try_get("description").map_err(database)?,
        event_types: serde_json::from_value(
            row.try_get::<Value, _>("event_types").map_err(database)?,
        )
        .map_err(invalid)?,
        filter_config: row
            .try_get::<Value, _>("filter_config")
            .map_err(database)?
            .as_object()
            .cloned()
            .unwrap_or_default(),
        retry_policy: serde_json::from_value(
            row.try_get::<Value, _>("retry_policy").map_err(database)?,
        )
        .map_err(invalid)?,
        delivery_target_id: row.try_get("delivery_target_id").map_err(database)?,
        enabled: row.try_get("enabled").map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
        updated_at: row.try_get("updated_at").map_err(database)?,
    })
}

fn row_webhook(row: PgRow) -> Result<WebhookEndpoint, RepositoryError> {
    Ok(WebhookEndpoint {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        name: row.try_get("name").map_err(database)?,
        url: row.try_get("url").map_err(database)?,
        secret: String::new(),
        secret_envelope: row.try_get("secret_envelope").map_err(database)?,
        secret_hint: row.try_get("secret_hint").map_err(database)?,
        description: row.try_get("description").map_err(database)?,
        event_types: serde_json::from_value(
            row.try_get::<Value, _>("event_types").map_err(database)?,
        )
        .map_err(invalid)?,
        enabled: row.try_get("enabled").map_err(database)?,
        failure_count: row.try_get("failure_count").map_err(database)?,
        last_failure_at: row.try_get("last_failure_at").map_err(database)?,
        last_triggered_at: row.try_get("last_triggered_at").map_err(database)?,
        circuit_breaker_open_until: row
            .try_get("circuit_breaker_open_until")
            .map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
        updated_at: row.try_get("updated_at").map_err(database)?,
    })
}

fn row_delivery(row: PgRow) -> Result<WebhookDelivery, RepositoryError> {
    Ok(WebhookDelivery {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        webhook_id: row.try_get("webhook_id").map_err(database)?,
        subscription_id: row.try_get("subscription_id").map_err(database)?,
        event_id: row.try_get("event_id").map_err(database)?,
        event_type: row.try_get("event_type").map_err(database)?,
        correlation_id: row.try_get("correlation_id").map_err(database)?,
        success: row.try_get("success").map_err(database)?,
        response_status_code: row.try_get("response_status_code").map_err(database)?,
        error_message: row.try_get("error_message").map_err(database)?,
        retry_count: row.try_get("retry_count").map_err(database)?,
        response_time_ms: row.try_get("response_time_ms").map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
    })
}

fn row_outbox(row: PgRow) -> Result<WebhookOutboxEvent, RepositoryError> {
    Ok(WebhookOutboxEvent {
        id: row.try_get("id").map_err(database)?,
        organization_id: row.try_get("organization_id").map_err(database)?,
        webhook_id: row.try_get("webhook_id").map_err(database)?,
        subscription_id: row.try_get("subscription_id").map_err(database)?,
        event_id: row.try_get("event_id").map_err(database)?,
        event_type: row.try_get("event_type").map_err(database)?,
        payload: row
            .try_get::<Value, _>("payload")
            .map_err(database)?
            .as_object()
            .cloned()
            .unwrap_or_default(),
        max_attempts: row.try_get("max_attempts").map_err(database)?,
        initial_backoff_seconds: row.try_get("initial_backoff_seconds").map_err(database)?,
        max_backoff_seconds: row.try_get("max_backoff_seconds").map_err(database)?,
        created_at: row.try_get("created_at").map_err(database)?,
        next_attempt_at: row.try_get("next_attempt_at").map_err(database)?,
        expires_at: row.try_get("expires_at").map_err(database)?,
        status: row.try_get("status").map_err(database)?,
        attempt_count: row.try_get("attempt_count").map_err(database)?,
        lease_token: row.try_get("lease_token").map_err(database)?,
        lease_expires_at: row.try_get("lease_expires_at").map_err(database)?,
        delivered_at: row.try_get("delivered_at").map_err(database)?,
        last_error_code: row.try_get("last_error_code").map_err(database)?,
        response_status_code: row.try_get("response_status_code").map_err(database)?,
    })
}

#[async_trait]
impl NotificationRepository for PgNotificationRepository {
    async fn save_notification(&self, item: Notification) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO notification_service.notifications (id,organization_id,recipient_id,recipient_email,recipient_phone,notification_type,template_id,subject,body,severity,link,data,status,priority,attempts,last_attempt_at,delivered_at,error_message,created_at,scheduled_at,read_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,recipient_id=EXCLUDED.recipient_id,recipient_email=EXCLUDED.recipient_email,recipient_phone=EXCLUDED.recipient_phone,notification_type=EXCLUDED.notification_type,template_id=EXCLUDED.template_id,subject=EXCLUDED.subject,body=EXCLUDED.body,severity=EXCLUDED.severity,link=EXCLUDED.link,data=EXCLUDED.data,status=EXCLUDED.status,priority=EXCLUDED.priority,attempts=EXCLUDED.attempts,last_attempt_at=EXCLUDED.last_attempt_at,delivered_at=EXCLUDED.delivered_at,error_message=EXCLUDED.error_message,scheduled_at=EXCLUDED.scheduled_at,read_at=EXCLUDED.read_at")
            .bind(&item.id).bind(&item.organization_id).bind(&item.recipient_id).bind(&item.recipient_email).bind(&item.recipient_phone).bind(type_name(item.notification_type))
            .bind(&item.template_id).bind(&item.subject).bind(&item.body).bind(&item.severity).bind(&item.link).bind(compose_notification_data(&item)?)
            .bind(status_name(item.status)).bind(item.priority.storage_name()).bind(item.attempts).bind(item.last_attempt_at).bind(item.delivered_at).bind(&item.error_message)
            .bind(item.created_at).bind(item.scheduled_at).bind(item.read_at).execute(&self.pool).await.map_err(database)?;
        Ok(())
    }
    async fn get_notification(&self, id: &str) -> Result<Option<Notification>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.notifications WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?
            .map(row_notification)
            .transpose()
    }
    async fn delete_notification(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(
            sqlx::query("DELETE FROM notification_service.notifications WHERE id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(database)?
                .rows_affected()
                == 1,
        )
    }
    async fn list_notifications(
        &self,
        organization_id: Option<&str>,
        recipient_id: Option<&str>,
        status: Option<NotificationStatus>,
    ) -> Result<Vec<Notification>, RepositoryError> {
        let mut query =
            QueryBuilder::new("SELECT * FROM notification_service.notifications WHERE 1=1");
        if let Some(value) = organization_id {
            query.push(" AND organization_id=").push_bind(value);
        }
        if let Some(value) = recipient_id {
            query.push(" AND recipient_id=").push_bind(value);
        }
        if let Some(value) = status {
            query.push(" AND status=").push_bind(status_name(value));
        }
        query.push(" ORDER BY created_at DESC");
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(database)?
            .into_iter()
            .map(row_notification)
            .collect()
    }
    async fn save_template(&self, item: NotificationTemplate) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO notification_service.notification_templates (id,organization_id,name,notification_type,subject_template,body_template,active,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,name=EXCLUDED.name,notification_type=EXCLUDED.notification_type,subject_template=EXCLUDED.subject_template,body_template=EXCLUDED.body_template,active=EXCLUDED.active,updated_at=EXCLUDED.updated_at")
            .bind(item.id).bind(item.organization_id).bind(item.name).bind(type_name(item.notification_type)).bind(item.subject_template).bind(item.body_template).bind(item.active).bind(item.created_at).bind(item.updated_at).execute(&self.pool).await.map_err(database)?;
        Ok(())
    }
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<Option<NotificationTemplate>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.notification_templates WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?
            .map(row_template)
            .transpose()
    }
    async fn list_templates(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<NotificationTemplate>, RepositoryError> {
        let rows = if let Some(value) = organization_id { sqlx::query("SELECT * FROM notification_service.notification_templates WHERE organization_id IS NULL OR organization_id=$1 ORDER BY name").bind(value).fetch_all(&self.pool).await } else { sqlx::query("SELECT * FROM notification_service.notification_templates ORDER BY name").fetch_all(&self.pool).await }.map_err(database)?;
        rows.into_iter().map(row_template).collect()
    }
    async fn save_subscription(&self, item: Subscription) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO notification_service.subscriptions (id,organization_id,name,description,event_types,delivery_channel,filter_config,retry_policy,delivery_target_id,enabled,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'WEBHOOK',$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,event_types=EXCLUDED.event_types,delivery_channel=EXCLUDED.delivery_channel,filter_config=EXCLUDED.filter_config,retry_policy=EXCLUDED.retry_policy,delivery_target_id=EXCLUDED.delivery_target_id,enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at")
            .bind(item.id).bind(item.organization_id).bind(item.name).bind(item.description).bind(json!(item.event_types)).bind(Value::Object(item.filter_config)).bind(json!(item.retry_policy)).bind(item.delivery_target_id).bind(item.enabled).bind(item.created_at).bind(item.updated_at).execute(&self.pool).await.map_err(database)?;
        Ok(())
    }
    async fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.subscriptions WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?
            .map(row_subscription)
            .transpose()
    }
    async fn list_subscriptions(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<Subscription>, RepositoryError> {
        let rows = if let Some(value)=organization_id { sqlx::query("SELECT * FROM notification_service.subscriptions WHERE organization_id=$1 ORDER BY created_at DESC").bind(value).fetch_all(&self.pool).await } else { sqlx::query("SELECT * FROM notification_service.subscriptions ORDER BY created_at DESC").fetch_all(&self.pool).await }.map_err(database)?;
        rows.into_iter().map(row_subscription).collect()
    }
    async fn delete_subscription(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(
            sqlx::query("DELETE FROM notification_service.subscriptions WHERE id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(database)?
                .rows_affected()
                == 1,
        )
    }
    async fn save_webhook(&self, item: WebhookEndpoint) -> Result<(), RepositoryError> {
        let envelope = item
            .secret_envelope
            .filter(|value| value.starts_with("vault:"))
            .ok_or_else(|| invalid("plaintext-only webhook persistence is forbidden"))?;
        let hint = item
            .secret_hint
            .filter(|value| value.chars().count() == 4)
            .ok_or_else(|| invalid("webhook secret hint is invalid"))?;
        sqlx::query("INSERT INTO notification_service.webhook_endpoints (id,organization_id,name,url,secret_envelope,secret_hint,description,event_types,enabled,failure_count,last_failure_at,last_triggered_at,circuit_breaker_open_until,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,url=EXCLUDED.url,secret_envelope=EXCLUDED.secret_envelope,secret_hint=EXCLUDED.secret_hint,description=EXCLUDED.description,event_types=EXCLUDED.event_types,enabled=EXCLUDED.enabled,failure_count=EXCLUDED.failure_count,last_failure_at=EXCLUDED.last_failure_at,last_triggered_at=EXCLUDED.last_triggered_at,circuit_breaker_open_until=EXCLUDED.circuit_breaker_open_until,updated_at=EXCLUDED.updated_at")
            .bind(item.id).bind(item.organization_id).bind(item.name).bind(item.url).bind(envelope).bind(hint).bind(item.description).bind(json!(item.event_types)).bind(item.enabled).bind(item.failure_count).bind(item.last_failure_at).bind(item.last_triggered_at).bind(item.circuit_breaker_open_until).bind(item.created_at).bind(item.updated_at).execute(&self.pool).await.map_err(database)?;
        Ok(())
    }
    async fn get_webhook(&self, id: &str) -> Result<Option<WebhookEndpoint>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.webhook_endpoints WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?
            .map(row_webhook)
            .transpose()
    }
    async fn list_webhooks(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<WebhookEndpoint>, RepositoryError> {
        let rows=if let Some(value)=organization_id{sqlx::query("SELECT * FROM notification_service.webhook_endpoints WHERE organization_id=$1 ORDER BY created_at DESC").bind(value).fetch_all(&self.pool).await}else{sqlx::query("SELECT * FROM notification_service.webhook_endpoints ORDER BY created_at DESC").fetch_all(&self.pool).await}.map_err(database)?;
        rows.into_iter().map(row_webhook).collect()
    }
    async fn delete_webhook(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(
            sqlx::query("DELETE FROM notification_service.webhook_endpoints WHERE id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(database)?
                .rows_affected()
                == 1,
        )
    }
    async fn save_webhook_delivery(&self, item: WebhookDelivery) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO notification_service.webhook_deliveries (id,organization_id,webhook_id,subscription_id,event_id,event_type,correlation_id,success,response_status_code,error_message,retry_count,response_time_ms,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(id) DO UPDATE SET correlation_id=EXCLUDED.correlation_id,success=EXCLUDED.success,response_status_code=EXCLUDED.response_status_code,error_message=EXCLUDED.error_message,retry_count=EXCLUDED.retry_count,response_time_ms=EXCLUDED.response_time_ms") .bind(item.id).bind(item.organization_id).bind(item.webhook_id).bind(item.subscription_id).bind(item.event_id).bind(item.event_type).bind(item.correlation_id).bind(item.success).bind(item.response_status_code).bind(item.error_message).bind(item.retry_count).bind(item.response_time_ms).bind(item.created_at).execute(&self.pool).await.map_err(database)?;
        Ok(())
    }
    async fn list_webhook_deliveries(
        &self,
        webhook_id: &str,
    ) -> Result<Vec<WebhookDelivery>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.webhook_deliveries WHERE webhook_id=$1 ORDER BY created_at DESC").bind(webhook_id).fetch_all(&self.pool).await.map_err(database)?.into_iter().map(row_delivery).collect()
    }
    async fn enqueue_webhook_event(
        &self,
        item: WebhookOutboxEvent,
    ) -> Result<bool, RepositoryError> {
        let result=sqlx::query("INSERT INTO notification_service.webhook_outbox (id,organization_id,webhook_id,subscription_id,event_id,event_type,payload,max_attempts,initial_backoff_seconds,max_backoff_seconds,status,attempt_count,next_attempt_at,lease_token,lease_expires_at,delivered_at,last_error_code,response_status_code,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) ON CONFLICT(event_id,subscription_id,webhook_id) DO NOTHING") .bind(item.id).bind(item.organization_id).bind(item.webhook_id).bind(item.subscription_id).bind(item.event_id).bind(item.event_type).bind(Value::Object(item.payload)).bind(item.max_attempts).bind(item.initial_backoff_seconds).bind(item.max_backoff_seconds).bind(item.status).bind(item.attempt_count).bind(item.next_attempt_at).bind(item.lease_token).bind(item.lease_expires_at).bind(item.delivered_at).bind(item.last_error_code).bind(item.response_status_code).bind(item.created_at).bind(item.expires_at).execute(&self.pool).await.map_err(database)?;
        Ok(result.rows_affected() == 1)
    }
    async fn claim_due_webhook_events(
        &self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookOutboxEvent>, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(database)?;
        sqlx::query("UPDATE notification_service.webhook_outbox SET status='expired',payload='{}'::json,lease_token=NULL,lease_expires_at=NULL,last_error_code='retention_expired' WHERE expires_at <= $1 AND status IN ('pending','retry','delivering')").bind(now).execute(&mut *tx).await.map_err(database)?;
        let rows=sqlx::query("UPDATE notification_service.webhook_outbox AS target SET status='delivering',attempt_count=target.attempt_count+1,lease_token=gen_random_uuid()::text,lease_expires_at=$2 FROM (SELECT id FROM notification_service.webhook_outbox WHERE expires_at>$1 AND ((status IN ('pending','retry') AND next_attempt_at<=$1) OR (status='delivering' AND lease_expires_at<=$1)) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $3) due WHERE target.id=due.id RETURNING target.*").bind(now).bind(lease_expires_at).bind(i64::try_from(limit.clamp(1,100)).unwrap_or(100)).fetch_all(&mut *tx).await.map_err(database)?;
        tx.commit().await.map_err(database)?;
        rows.into_iter().map(row_outbox).collect()
    }
    async fn mark_webhook_event_delivered(
        &self,
        id: &str,
        lease_token: &str,
        delivered_at: DateTime<Utc>,
        response_status_code: i32,
    ) -> Result<bool, RepositoryError> {
        Ok(sqlx::query("UPDATE notification_service.webhook_outbox SET status='delivered',payload='{}'::json,delivered_at=$3,response_status_code=$4,lease_token=NULL,lease_expires_at=NULL,last_error_code=NULL WHERE id=$1 AND status='delivering' AND lease_token=$2").bind(id).bind(lease_token).bind(delivered_at).bind(response_status_code).execute(&self.pool).await.map_err(database)?.rows_affected()==1)
    }
    async fn mark_webhook_event_failed(
        &self,
        id: &str,
        lease_token: &str,
        next_attempt_at: DateTime<Utc>,
        terminal: bool,
        error_code: &str,
        response_status_code: Option<i32>,
    ) -> Result<bool, RepositoryError> {
        let status = if terminal { "dead_letter" } else { "retry" };
        Ok(sqlx::query("UPDATE notification_service.webhook_outbox SET status=$3,payload=CASE WHEN $4 THEN '{}'::json ELSE payload END,next_attempt_at=$5,lease_token=NULL,lease_expires_at=NULL,last_error_code=left($6,128),response_status_code=$7 WHERE id=$1 AND status='delivering' AND lease_token=$2").bind(id).bind(lease_token).bind(status).bind(terminal).bind(next_attempt_at).bind(error_code).bind(response_status_code).execute(&self.pool).await.map_err(database)?.rows_affected()==1)
    }
    async fn get_webhook_outbox_event(
        &self,
        id: &str,
    ) -> Result<Option<WebhookOutboxEvent>, RepositoryError> {
        sqlx::query("SELECT * FROM notification_service.webhook_outbox WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?
            .map(row_outbox)
            .transpose()
    }
}

trait PriorityName {
    fn storage_name(self) -> &'static str;
}
impl PriorityName for NotificationPriority {
    fn storage_name(self) -> &'static str {
        match self {
            NotificationPriority::Low => "LOW",
            NotificationPriority::Normal => "NORMAL",
            NotificationPriority::High => "HIGH",
            NotificationPriority::Critical => "CRITICAL",
        }
    }
}
