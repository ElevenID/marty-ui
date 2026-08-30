use std::{
    collections::{BTreeSet, HashMap},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::sync::mpsc;

use crate::credential_management::{CredentialLifecycleEvent, CredentialLifecycleEventSink};

const DEFAULT_SUBSCRIBER_CAPACITY: usize = 256;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialLifecycleEventFilter {
    organization_id: Option<String>,
    credential_template_id: Option<String>,
    event_types: BTreeSet<String>,
}

impl CredentialLifecycleEventFilter {
    #[must_use]
    pub fn new(
        organization_id: Option<&str>,
        credential_template_id: Option<&str>,
        event_types: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            organization_id: optional_filter(organization_id),
            credential_template_id: optional_filter(credential_template_id),
            event_types: event_types.into_iter().collect(),
        }
    }

    fn matches(&self, event: &CredentialLifecycleEvent) -> bool {
        self.organization_id
            .as_ref()
            .is_none_or(|value| value == &event.organization_id)
            && self
                .credential_template_id
                .as_ref()
                .is_none_or(|value| value == &event.credential_template_id)
            && (self.event_types.is_empty() || self.event_types.contains(&event.event_type))
    }
}

#[derive(Clone)]
pub struct CredentialLifecycleEventBus {
    inner: Arc<EventBusInner>,
}

impl std::fmt::Debug for CredentialLifecycleEventBus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialLifecycleEventBus")
            .field("subscriber_capacity", &self.inner.subscriber_capacity)
            .finish_non_exhaustive()
    }
}

impl Default for CredentialLifecycleEventBus {
    fn default() -> Self {
        Self::new(DEFAULT_SUBSCRIBER_CAPACITY)
    }
}

impl CredentialLifecycleEventBus {
    #[must_use]
    pub fn new(subscriber_capacity: usize) -> Self {
        Self {
            inner: Arc::new(EventBusInner {
                next_id: AtomicU64::new(1),
                subscriber_capacity: subscriber_capacity.max(1),
                subscribers: Mutex::new(HashMap::new()),
            }),
        }
    }

    #[must_use]
    pub fn subscribe(
        &self,
        filter: CredentialLifecycleEventFilter,
    ) -> CredentialLifecycleEventSubscription {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(self.inner.subscriber_capacity);
        self.inner
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, sender);
        CredentialLifecycleEventSubscription {
            id,
            filter,
            receiver,
            inner: self.inner.clone(),
        }
    }

    #[cfg(test)]
    fn subscriber_count(&self) -> usize {
        self.inner
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

#[async_trait]
impl CredentialLifecycleEventSink for CredentialLifecycleEventBus {
    async fn emit(&self, event: CredentialLifecycleEvent) {
        let mut subscribers = self
            .inner
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        subscribers.retain(
            |subscriber_id, subscriber| match subscriber.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        subscriber_id,
                        "dropping credential lifecycle event for slow subscriber"
                    );
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
        );
    }
}

struct EventBusInner {
    next_id: AtomicU64,
    subscriber_capacity: usize,
    subscribers: Mutex<HashMap<u64, mpsc::Sender<CredentialLifecycleEvent>>>,
}

pub struct CredentialLifecycleEventSubscription {
    id: u64,
    filter: CredentialLifecycleEventFilter,
    receiver: mpsc::Receiver<CredentialLifecycleEvent>,
    inner: Arc<EventBusInner>,
}

impl std::fmt::Debug for CredentialLifecycleEventSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialLifecycleEventSubscription")
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl CredentialLifecycleEventSubscription {
    pub async fn recv(&mut self) -> Option<CredentialLifecycleEvent> {
        std::future::poll_fn(|context| Pin::new(&mut *self).poll_next(context)).await
    }
}

impl futures_core::Stream for CredentialLifecycleEventSubscription {
    type Item = CredentialLifecycleEvent;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.receiver.poll_recv(context) {
                Poll::Ready(Some(event)) if self.filter.matches(&event) => {
                    return Poll::Ready(Some(event));
                }
                Poll::Ready(Some(_)) => {}
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for CredentialLifecycleEventSubscription {
    fn drop(&mut self) {
        self.inner
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

fn optional_filter(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn event(
        event_type: &str,
        organization_id: &str,
        credential_template_id: &str,
    ) -> CredentialLifecycleEvent {
        CredentialLifecycleEvent {
            event_type: event_type.to_owned(),
            credential_id: format!("credential-{event_type}"),
            organization_id: organization_id.to_owned(),
            credential_template_id: credential_template_id.to_owned(),
            status: event_type.to_owned(),
            timestamp: Utc
                .with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
                .single()
                .expect("timestamp"),
        }
    }

    #[tokio::test]
    async fn subscribers_preserve_the_legacy_filter_contract() {
        let bus = CredentialLifecycleEventBus::default();
        let mut subscription = bus.subscribe(CredentialLifecycleEventFilter::new(
            Some("org-a"),
            Some("template-a"),
            ["revoked".to_owned(), "reinstated".to_owned()],
        ));

        bus.emit(event("revoked", "org-b", "template-a")).await;
        bus.emit(event("suspended", "org-a", "template-a")).await;
        bus.emit(event("revoked", "org-a", "template-b")).await;
        bus.emit(event("reinstated", "org-a", "template-a")).await;

        let received = subscription.recv().await.expect("matching event");
        assert_eq!(received.event_type, "reinstated");
        assert_eq!(received.organization_id, "org-a");
        assert_eq!(received.credential_template_id, "template-a");
    }

    #[tokio::test]
    async fn filter_values_are_exact_like_the_protobuf_contract() {
        let bus = CredentialLifecycleEventBus::default();
        let mut whitespace = bus.subscribe(CredentialLifecycleEventFilter::new(
            Some(" org-a "),
            None,
            std::iter::empty(),
        ));
        let mut explicit_empty_event = bus.subscribe(CredentialLifecycleEventFilter::new(
            None,
            None,
            [String::new()],
        ));
        bus.emit(event("revoked", "org-a", "template-a")).await;

        assert!(matches!(
            whitespace.receiver.try_recv(),
            Ok(CredentialLifecycleEvent { .. })
        ));
        assert!(matches!(
            explicit_empty_event.receiver.try_recv(),
            Ok(CredentialLifecycleEvent { .. })
        ));
        assert!(!whitespace
            .filter
            .matches(&event("revoked", "org-a", "template-a")));
        assert!(!explicit_empty_event
            .filter
            .matches(&event("revoked", "org-a", "template-a")));
    }

    #[tokio::test]
    async fn slow_subscribers_drop_new_events_without_blocking_mutations() {
        let bus = CredentialLifecycleEventBus::new(1);
        let mut subscription = bus.subscribe(CredentialLifecycleEventFilter::default());

        bus.emit(event("first", "org-a", "template-a")).await;
        bus.emit(event("dropped", "org-a", "template-a")).await;
        assert_eq!(
            subscription.recv().await.expect("first event").event_type,
            "first"
        );

        bus.emit(event("next", "org-a", "template-a")).await;
        assert_eq!(
            subscription.recv().await.expect("next event").event_type,
            "next"
        );
    }

    #[tokio::test]
    async fn dropping_a_subscription_removes_it_from_the_registry() {
        let bus = CredentialLifecycleEventBus::default();
        let subscription = bus.subscribe(CredentialLifecycleEventFilter::default());
        assert_eq!(bus.subscriber_count(), 1);
        drop(subscription);
        assert_eq!(bus.subscriber_count(), 0);
    }
}
