use crate::proto::DomainEvent;
use chrono::{SecondsFormat, Utc};
use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct SubscriptionFilter {
    pub event_types: HashSet<String>,
    pub organization_id: String,
    pub aggregate_type: String,
}

impl SubscriptionFilter {
    fn matches(&self, event: &DomainEvent) -> bool {
        (self.event_types.is_empty() || self.event_types.contains(&event.event_type))
            && (self.organization_id.is_empty() || self.organization_id == event.organization_id)
            && (self.aggregate_type.is_empty() || self.aggregate_type == event.aggregate_type)
    }
}

#[derive(Debug)]
struct Subscriber {
    generation: u64,
    filter: SubscriptionFilter,
    sender: mpsc::Sender<DomainEvent>,
}

#[derive(Debug, Default)]
struct Inner {
    subscribers: Mutex<HashMap<String, Subscriber>>,
    next_generation: AtomicU64,
    published: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct EventBus {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Subscription {
    pub id: String,
    generation: u64,
    receiver: mpsc::Receiver<DomainEvent>,
    bus: EventBus,
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<DomainEvent> {
        self.receiver.recv().await
    }

    pub fn into_stream(self) -> impl futures_core::Stream<Item = DomainEvent> {
        self
    }
}

impl futures_core::Stream for Subscription {
    type Item = DomainEvent;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let bus = self.bus.clone();
        let id = self.id.clone();
        let generation = self.generation;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                bus.unsubscribe_generation(&id, generation).await;
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub subscribers: usize,
    pub published: u64,
    pub delivered: u64,
    pub dropped: u64,
}

impl EventBus {
    pub async fn subscribe(
        &self,
        requested_id: String,
        filter: SubscriptionFilter,
    ) -> Subscription {
        let id = if requested_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            requested_id
        };
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = mpsc::channel(SUBSCRIBER_QUEUE_CAPACITY);
        self.inner.subscribers.lock().await.insert(
            id.clone(),
            Subscriber {
                generation,
                filter,
                sender,
            },
        );
        info!(subscriber_id = %id, "event subscriber registered");
        Subscription {
            id,
            generation,
            receiver,
            bus: self.clone(),
        }
    }

    pub async fn publish(&self, mut event: DomainEvent) -> i32 {
        if event.event_id.is_empty() {
            event.event_id = Uuid::new_v4().to_string();
        }
        if event.timestamp.is_empty() {
            event.timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
        }

        self.inner.published.fetch_add(1, Ordering::Relaxed);
        let mut delivered = 0i32;
        let mut stale = Vec::new();
        let subscribers = self.inner.subscribers.lock().await;
        for (id, subscriber) in subscribers.iter() {
            if !subscriber.filter.matches(&event) {
                continue;
            }
            match subscriber.sender.try_send(event.clone()) {
                Ok(()) => {
                    delivered = delivered.saturating_add(1);
                    self.inner.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                    warn!(subscriber_id = %id, event_type = %event.event_type, "dropping event for slow subscriber");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    stale.push((id.clone(), subscriber.generation))
                }
            }
        }
        drop(subscribers);
        for (id, generation) in stale {
            self.unsubscribe_generation(&id, generation).await;
        }
        delivered
    }

    pub async fn unsubscribe(&self, id: &str) {
        if self.inner.subscribers.lock().await.remove(id).is_some() {
            info!(subscriber_id = %id, "event subscriber removed");
        }
    }

    async fn unsubscribe_generation(&self, id: &str, generation: u64) {
        let mut subscribers = self.inner.subscribers.lock().await;
        if subscribers
            .get(id)
            .is_some_and(|subscriber| subscriber.generation == generation)
        {
            subscribers.remove(id);
            info!(subscriber_id = %id, "event subscriber removed");
        }
    }

    pub async fn metrics(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            subscribers: self.inner.subscribers.lock().await.len(),
            published: self.inner.published.load(Ordering::Relaxed),
            delivered: self.inner.delivered.load(Ordering::Relaxed),
            dropped: self.inner.dropped.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(organization_id: &str, event_type: &str) -> DomainEvent {
        DomainEvent {
            event_id: "event-1".into(),
            event_type: event_type.into(),
            aggregate_id: "aggregate-1".into(),
            aggregate_type: "application".into(),
            organization_id: organization_id.into(),
            data: HashMap::new(),
            timestamp: "2026-08-06T12:00:00+00:00".into(),
            correlation_id: String::new(),
        }
    }

    #[tokio::test]
    async fn filters_events_by_tenant_type_and_aggregate() {
        let bus = EventBus::default();
        let mut subscription = bus
            .subscribe(
                "subscriber-a".into(),
                SubscriptionFilter {
                    event_types: ["application.approved".to_string()].into_iter().collect(),
                    organization_id: "org-a".into(),
                    aggregate_type: "application".into(),
                },
            )
            .await;

        assert_eq!(bus.publish(event("org-b", "application.approved")).await, 0);
        assert_eq!(bus.publish(event("org-a", "application.rejected")).await, 0);
        assert_eq!(bus.publish(event("org-a", "application.approved")).await, 1);
        assert_eq!(
            subscription
                .recv()
                .await
                .expect("matching event")
                .organization_id,
            "org-a"
        );
    }

    #[tokio::test]
    async fn drops_for_slow_subscriber_without_blocking_publishers() {
        let bus = EventBus::default();
        let _subscription = bus
            .subscribe(
                "slow".into(),
                SubscriptionFilter {
                    event_types: HashSet::new(),
                    organization_id: String::new(),
                    aggregate_type: String::new(),
                },
            )
            .await;

        for _ in 0..SUBSCRIBER_QUEUE_CAPACITY {
            assert_eq!(bus.publish(event("org-a", "event")).await, 1);
        }
        assert_eq!(bus.publish(event("org-a", "event")).await, 0);
        assert_eq!(bus.metrics().await.dropped, 1);
    }

    #[tokio::test]
    async fn replacing_duplicate_id_does_not_let_old_drop_remove_new_subscription() {
        let bus = EventBus::default();
        let old = bus
            .subscribe(
                "same-id".into(),
                SubscriptionFilter {
                    event_types: HashSet::new(),
                    organization_id: "old".into(),
                    aggregate_type: String::new(),
                },
            )
            .await;
        let mut current = bus
            .subscribe(
                "same-id".into(),
                SubscriptionFilter {
                    event_types: HashSet::new(),
                    organization_id: "new".into(),
                    aggregate_type: String::new(),
                },
            )
            .await;
        drop(old);
        tokio::task::yield_now().await;

        assert_eq!(bus.publish(event("new", "event")).await, 1);
        assert_eq!(
            current.recv().await.expect("current event").organization_id,
            "new"
        );
    }
}
