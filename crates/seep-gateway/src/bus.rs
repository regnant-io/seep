//! The event bus.
//!
//! Every subsystem publishes here and nothing subscribes to anything else. That
//! indirection is what keeps the gateway from becoming a web of direct calls: the
//! runner does not know the web UI exists, and adding a sixth channel does not
//! mean editing the incident engine.
//!
//! The bus is lossy by design. A browser tab that has been asleep for an hour
//! must not be able to stall a production run by failing to read its socket — so
//! slow subscribers lose events and are *told* they lost them, rather than
//! applying backpressure all the way up into the executor.

use seep_proto::event::{Event, EventEnvelope};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Publishes events and hands out subscriptions.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<EventEnvelope>,
    sequence: Arc<AtomicU64>,
    /// Recent events, so a reconnecting client can catch up on what it missed
    /// instead of reloading the world.
    history: Arc<parking_history::History>,
}

/// A tiny ring buffer. Kept in its own module so the lock is not reachable from
/// anywhere that could hold it across an await.
mod parking_history {
    use seep_proto::event::EventEnvelope;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    pub struct History {
        entries: Mutex<VecDeque<EventEnvelope>>,
        capacity: usize,
    }

    impl History {
        pub fn new(capacity: usize) -> Self {
            Self { entries: Mutex::new(VecDeque::with_capacity(capacity)), capacity }
        }

        pub fn push(&self, envelope: EventEnvelope) {
            if let Ok(mut entries) = self.entries.lock() {
                if entries.len() >= self.capacity {
                    entries.pop_front();
                }
                entries.push_back(envelope);
            }
        }

        pub fn since(&self, sequence: u64, limit: usize) -> Vec<EventEnvelope> {
            match self.entries.lock() {
                Ok(entries) => entries
                    .iter()
                    .filter(|e| e.seq > sequence)
                    .take(limit)
                    .cloned()
                    .collect(),
                Err(_) => Vec::new(),
            }
        }

        pub fn len(&self) -> usize {
            self.entries.lock().map(|e| e.len()).unwrap_or(0)
        }
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(64));
        Self {
            sender,
            sequence: Arc::new(AtomicU64::new(0)),
            history: Arc::new(parking_history::History::new(capacity.clamp(64, 4_096))),
        }
    }

    /// Publish an event, returning its sequence number.
    pub fn publish(&self, event: Event) -> u64 {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let envelope = EventEnvelope::new(seq, event);
        self.history.push(envelope.clone());
        // An error means nobody is listening, which is a normal state for a
        // headless gateway and not worth logging.
        let _ = self.sender.send(envelope);
        seq
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.sender.subscribe()
    }

    /// Events after a given sequence number, for a reconnecting client.
    pub fn replay(&self, after: u64, limit: usize) -> Vec<EventEnvelope> {
        self.history.since(after, limit)
    }

    pub fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    pub fn buffered(&self) -> usize {
        self.history.len()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(2_048)
    }
}

/// Read from a subscription, converting lag into an explicit event.
///
/// A client that silently misses events would render a view with an invisible
/// hole in it — a run that appears stuck because its completion was dropped. This
/// turns that into something the UI can show.
pub async fn next_event(
    receiver: &mut broadcast::Receiver<EventEnvelope>,
) -> Option<EventEnvelope> {
    match receiver.recv().await {
        Ok(envelope) => Some(envelope),
        // Lag is reported rather than retried. Looping to catch up would hide
        // the gap, and the subscriber needs to know its view has one.
        Err(broadcast::error::RecvError::Lagged(dropped)) => {
            Some(EventEnvelope::new(0, Event::SubscriberLagged { dropped }))
        }
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::ids::{IncidentId, SessionId};

    fn notice(message: &str) -> Event {
        Event::SystemNotice { level: "info".into(), message: message.into() }
    }

    #[tokio::test]
    async fn a_published_event_reaches_subscribers() {
        let bus = EventBus::new(64);
        let mut receiver = bus.subscribe();
        bus.publish(notice("hello"));

        let envelope = next_event(&mut receiver).await.unwrap();
        assert_eq!(envelope.seq, 1);
        assert!(matches!(envelope.event, Event::SystemNotice { .. }));
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic() {
        let bus = EventBus::new(64);
        assert_eq!(bus.publish(notice("a")), 1);
        assert_eq!(bus.publish(notice("b")), 2);
        assert_eq!(bus.publish(notice("c")), 3);
        assert_eq!(bus.current_sequence(), 3);
    }

    #[tokio::test]
    async fn publishing_with_no_subscribers_is_fine() {
        // A headless gateway is a supported way to run.
        let bus = EventBus::new(64);
        assert_eq!(bus.subscriber_count(), 0);
        bus.publish(notice("into the void"));
        assert_eq!(bus.current_sequence(), 1);
    }

    #[tokio::test]
    async fn a_reconnecting_client_can_replay_what_it_missed() {
        let bus = EventBus::new(64);
        for i in 0..5 {
            bus.publish(notice(&format!("event {}", i)));
        }
        let missed = bus.replay(2, 100);
        assert_eq!(missed.len(), 3);
        assert_eq!(missed[0].seq, 3);
    }

    #[tokio::test]
    async fn replay_respects_its_limit() {
        let bus = EventBus::new(256);
        for i in 0..50 {
            bus.publish(notice(&format!("event {}", i)));
        }
        assert_eq!(bus.replay(0, 10).len(), 10);
    }

    #[tokio::test]
    async fn history_is_bounded() {
        // Otherwise a long-running gateway accumulates every event it ever sent.
        let bus = EventBus::new(64);
        for i in 0..500 {
            bus.publish(notice(&format!("event {}", i)));
        }
        assert!(bus.buffered() <= 64);
    }

    #[tokio::test]
    async fn a_slow_subscriber_is_told_it_fell_behind() {
        // The alternative — silently missing events — renders a view with an
        // invisible hole in it.
        let bus = EventBus::new(64);
        let mut receiver = bus.subscribe();
        for i in 0..200 {
            bus.publish(notice(&format!("event {}", i)));
        }
        let envelope = next_event(&mut receiver).await.unwrap();
        assert!(
            matches!(envelope.event, Event::SubscriberLagged { .. }),
            "expected a lag notice, got {:?}",
            envelope.event
        );
    }

    #[tokio::test]
    async fn a_slow_subscriber_does_not_block_publishers() {
        // The property that keeps a sleeping browser tab from stalling a run.
        let bus = EventBus::new(64);
        let _slow = bus.subscribe();
        for i in 0..10_000 {
            bus.publish(notice(&format!("event {}", i)));
        }
        assert_eq!(bus.current_sequence(), 10_000);
    }

    #[tokio::test]
    async fn dropping_every_subscriber_closes_the_stream() {
        let bus = EventBus::new(64);
        let mut receiver = bus.subscribe();
        drop(bus);
        assert!(next_event(&mut receiver).await.is_none());
    }

    #[tokio::test]
    async fn events_carry_their_routing_metadata() {
        let bus = EventBus::new(64);
        let session = SessionId::generate();
        bus.publish(Event::SessionDelta { session_id: session.clone(), text: "hi".into() });
        bus.publish(Event::IncidentOpened {
            incident_id: IncidentId::generate(),
            number: 1,
            title: "t".into(),
            severity: "S1".into(),
        });

        let events = bus.replay(0, 10);
        assert_eq!(events[0].event.session_id(), Some(&session));
        assert!(events[1].event.is_notable());
    }
}
