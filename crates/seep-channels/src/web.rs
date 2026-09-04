//! The built-in web chat.
//!
//! Unlike the other adapters this one has no external service. Messages are
//! handed to it by the gateway's own WebSocket handler and broadcast back to
//! connected browsers.
//!
//! It matters that this exists as a *channel* rather than as a special case
//! inside the gateway: it means the browser goes through exactly the same
//! allowlist, approval, and audit path as Slack does, instead of getting a
//! privileged side door because it happens to be first-party.

use async_trait::async_trait;
use seep_proto::channel::{
    ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage, OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// A message destined for connected browsers.
#[derive(Debug, Clone)]
pub struct WebDelivery {
    pub target: ChannelTarget,
    pub message_id: String,
    pub message: OutboundMessage,
    /// True when this replaces an earlier message rather than adding one.
    pub is_update: bool,
}

pub struct WebChannel {
    id: ChannelId,
    outbound: broadcast::Sender<WebDelivery>,
    /// Handed out as message IDs so updates can address an earlier message.
    counter: AtomicU64,
    can_approve: bool,
}

impl WebChannel {
    pub fn new(buffer: usize) -> Self {
        let (outbound, _) = broadcast::channel(buffer.max(64));
        Self {
            id: ChannelId::derive("web"),
            outbound,
            counter: AtomicU64::new(1),
            can_approve: true,
        }
    }

    /// Subscribe to messages headed for browsers.
    pub fn subscribe(&self) -> broadcast::Receiver<WebDelivery> {
        self.outbound.subscribe()
    }

    /// Number of connected browser sessions.
    pub fn connected(&self) -> usize {
        self.outbound.receiver_count()
    }

    /// A conversation target for one browser session.
    pub fn target_for(&self, session: &str) -> ChannelTarget {
        ChannelTarget::new(self.id.clone(), ChannelKind::Web, session.to_string())
    }

    /// Build an inbound message from what a browser sent.
    ///
    /// The operator is resolved by the gateway from the authenticated session, not
    /// from anything the browser claims — a field in a WebSocket frame is not an
    /// identity.
    pub fn inbound_from(
        &self,
        session: &str,
        sender_id: &str,
        text: &str,
        action: Option<String>,
    ) -> InboundMessage {
        InboundMessage {
            target: self.target_for(session),
            sender_id: sender_id.to_string(),
            sender_name: sender_id.to_string(),
            operator: None,
            text: text.to_string(),
            attachments: vec![],
            action,
            interaction_token: None,
            source_message_id: None,
            mentioned: true,
            direct: true,
            received_at: seep_proto::now_rfc3339(),
            raw: None,
        }
    }
}

#[async_trait]
impl crate::Channel for WebChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Web
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "web"
    }

    fn can_approve(&self) -> bool {
        self.can_approve
    }

    fn is_allowed(&self, _account_id: &str) -> bool {
        // Reaching the web UI already required the gateway's bearer token or an
        // authenticated session, so anyone who gets here is known. The operator
        // identity is still resolved from the session, not asserted by the page.
        true
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        // Broadcast to every connected browser rather than to one session.
        Some(ChannelTarget::new(self.id.clone(), ChannelKind::Web, "*".to_string()))
    }

    async fn run(
        self: Arc<Self>,
        _inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Inbound messages arrive through the gateway's WebSocket handler.
        cancel.cancelled().await;
        Ok(())
    }

    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let message_id = format!("web_{}", self.counter.fetch_add(1, Ordering::Relaxed));
        // A send with no browsers attached is not an error: the gateway is
        // allowed to run headless, and the audit log is the durable record
        // regardless of who happened to be watching.
        let _ = self.outbound.send(WebDelivery {
            target: target.clone(),
            message_id: message_id.clone(),
            message: message.clone(),
            is_update: false,
        });
        Ok(ChannelMessageRef { target: target.clone(), message_id })
    }

    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        let _ = self.outbound.send(WebDelivery {
            target: reference.target.clone(),
            message_id: reference.message_id.clone(),
            message: message.clone(),
            is_update: true,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Channel as _;

    #[tokio::test]
    async fn a_sent_message_reaches_subscribers() {
        let channel = WebChannel::new(16);
        let mut receiver = channel.subscribe();

        let target = channel.target_for("sess_1");
        let reference = channel
            .send(&target, &OutboundMessage::text("hello from seep"))
            .await
            .unwrap();

        let delivered = receiver.recv().await.unwrap();
        assert_eq!(delivered.message.text, "hello from seep");
        assert_eq!(delivered.message_id, reference.message_id);
        assert!(!delivered.is_update);
    }

    #[tokio::test]
    async fn an_update_is_flagged_and_addresses_the_original() {
        let channel = WebChannel::new(16);
        let mut receiver = channel.subscribe();
        let target = channel.target_for("sess_1");

        let reference = channel.send(&target, &OutboundMessage::text("pending")).await.unwrap();
        let _ = receiver.recv().await.unwrap();

        channel
            .update(&reference, &OutboundMessage::text("approved by alice"))
            .await
            .unwrap();
        let delivered = receiver.recv().await.unwrap();
        assert!(delivered.is_update);
        assert_eq!(delivered.message_id, reference.message_id);
        assert_eq!(delivered.message.text, "approved by alice");
    }

    #[tokio::test]
    async fn sending_with_no_browsers_attached_is_not_an_error() {
        // The gateway is allowed to run headless.
        let channel = WebChannel::new(16);
        assert_eq!(channel.connected(), 0);
        assert!(channel
            .send(&channel.target_for("sess_1"), &OutboundMessage::text("x"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn message_ids_are_unique() {
        let channel = WebChannel::new(16);
        let target = channel.target_for("sess_1");
        let first = channel.send(&target, &OutboundMessage::text("a")).await.unwrap();
        let second = channel.send(&target, &OutboundMessage::text("b")).await.unwrap();
        assert_ne!(first.message_id, second.message_id);
    }

    #[test]
    fn inbound_messages_never_carry_a_self_asserted_operator() {
        // Identity comes from the authenticated session, not from the page.
        let channel = WebChannel::new(16);
        let message = channel.inbound_from("sess_1", "browser", "hello", None);
        assert!(message.operator.is_none());
        assert!(message.direct);
        assert!(message.should_handle(true));
    }

    #[test]
    fn button_presses_carry_their_action() {
        let channel = WebChannel::new(16);
        let message =
            channel.inbound_from("sess_1", "browser", "", Some("approve:apr_x".into()));
        assert_eq!(message.action.as_deref(), Some("approve:apr_x"));
    }

    #[test]
    fn subscriber_count_reflects_connections() {
        let channel = WebChannel::new(16);
        let one = channel.subscribe();
        assert_eq!(channel.connected(), 1);
        let two = channel.subscribe();
        assert_eq!(channel.connected(), 2);
        drop(one);
        drop(two);
        assert_eq!(channel.connected(), 0);
    }
}
