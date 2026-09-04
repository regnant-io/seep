//! Running every configured channel at once.
//!
//! The manager owns the adapters, funnels their inbound messages into a single
//! stream, and fans outbound messages back out. It is also where the two rules
//! that matter most are actually applied — once, here, rather than being repeated
//! (and eventually forgotten) in each adapter:
//!
//! * A message from an account that is not on the allowlist is dropped before it
//!   ever reaches the agent, and the attempt is logged.
//! * A channel configured as notify-only never carries an approval action, even
//!   if a button somehow appears on one.

use seep_proto::channel::{
    ChannelDescriptor, ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage,
    OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::Channel;

/// Why a message was not delivered to the agent.
#[derive(Debug, Clone, PartialEq)]
pub enum Rejection {
    /// The sender is not on this channel's allowlist.
    UnknownSender { channel: ChannelKind, account: String },
    /// The channel may notify but not authorize.
    ApprovalNotPermitted { channel: ChannelKind },
    /// A group message with no mention.
    NotAddressed,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::UnknownSender { channel, account } => write!(
                f,
                "ignored a message from unrecognised {} account {}",
                channel, account
            ),
            Rejection::ApprovalNotPermitted { channel } => {
                write!(f, "{} is configured for notifications only, not approvals", channel)
            }
            Rejection::NotAddressed => write!(f, "group message with no mention"),
        }
    }
}

/// Owns and drives every configured channel.
pub struct ChannelManager {
    channels: BTreeMap<String, Arc<dyn Channel>>,
    require_mention_in_groups: bool,
}

impl ChannelManager {
    pub fn new(require_mention_in_groups: bool) -> Self {
        Self { channels: BTreeMap::new(), require_mention_in_groups }
    }

    pub fn register(&mut self, channel: Arc<dyn Channel>) {
        self.channels.insert(channel.id().to_string(), channel);
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn get(&self, id: &ChannelId) -> Option<&Arc<dyn Channel>> {
        self.channels.get(id.as_str())
    }

    pub fn by_kind(&self, kind: ChannelKind) -> Option<&Arc<dyn Channel>> {
        self.channels.values().find(|c| c.kind() == kind)
    }

    pub fn all(&self) -> impl Iterator<Item = &Arc<dyn Channel>> {
        self.channels.values()
    }

    pub fn descriptors(&self) -> Vec<ChannelDescriptor> {
        self.channels.values().map(|c| c.descriptor()).collect()
    }

    /// Start every channel's receive loop.
    ///
    /// Each runs in its own task: one platform being down must not stop the
    /// others, because the whole point of five channels is that you can still be
    /// reached when one of them is having an outage.
    pub fn start(
        &self,
        inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        self.channels
            .values()
            .map(|channel| {
                let channel = Arc::clone(channel);
                let inbound = inbound.clone();
                let cancel = cancel.clone();
                let name = channel.name().to_string();
                tokio::spawn(async move {
                    if let Err(e) = channel.run(inbound, cancel).await {
                        tracing::error!(channel = %name, error = %e, "channel stopped with an error");
                    }
                })
            })
            .collect()
    }

    /// Decide whether an inbound message should reach the agent.
    ///
    /// Returns the message with nothing else changed on success. The operator is
    /// resolved separately, by the gateway, against the operator registry — an
    /// allowlist entry says "this account may talk to us", not "this account is
    /// Alice".
    pub fn admit(&self, message: InboundMessage) -> Result<InboundMessage, Rejection> {
        let Some(channel) = self.channels.get(message.target.channel_id.as_str()) else {
            return Err(Rejection::UnknownSender {
                channel: message.target.kind,
                account: message.sender_id.clone(),
            });
        };

        if !channel.is_allowed(&message.sender_id) {
            return Err(Rejection::UnknownSender {
                channel: channel.kind(),
                account: message.sender_id.clone(),
            });
        }

        // An approval arriving through a notify-only channel is refused here,
        // before the approval engine ever sees it.
        if message.action.is_some() && !channel.can_approve() && is_decision_action(&message) {
            return Err(Rejection::ApprovalNotPermitted { channel: channel.kind() });
        }

        if !message.should_handle(self.require_mention_in_groups) {
            return Err(Rejection::NotAddressed);
        }

        Ok(message)
    }

    /// Send to one target.
    pub async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let channel = self
            .channels
            .get(target.channel_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("no channel registered as {}", target.channel_id))?;
        channel.send(target, message).await
    }

    /// Rewrite an already-delivered message.
    pub async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        let channel = self
            .channels
            .get(reference.target.channel_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("no channel registered as {}", reference.target.channel_id))?;
        channel.update(reference, message).await
    }

    pub async fn acknowledge(&self, message: &InboundMessage) -> anyhow::Result<()> {
        if let Some(channel) = self.channels.get(message.target.channel_id.as_str()) {
            channel.acknowledge(message).await?;
        }
        Ok(())
    }

    /// Broadcast to every channel's default target.
    ///
    /// Failures are collected rather than propagated: an unreachable Slack must
    /// not stop the same incident notice reaching Telegram, which is the entire
    /// reason for configuring more than one channel.
    pub async fn broadcast(&self, message: &OutboundMessage) -> Vec<ChannelMessageRef> {
        let mut delivered = Vec::new();
        for channel in self.channels.values() {
            let Some(target) = channel.default_target() else { continue };
            match channel.send(&target, message).await {
                Ok(reference) => delivered.push(reference),
                Err(e) => tracing::warn!(
                    channel = channel.name(),
                    error = %e,
                    "could not deliver broadcast"
                ),
            }
        }
        delivered
    }

    /// Broadcast only to channels permitted to carry approvals.
    pub async fn broadcast_approval(&self, message: &OutboundMessage) -> Vec<ChannelMessageRef> {
        self.broadcast_approval_except(message, &ChannelId::parse("none")).await
    }

    /// The same, skipping one channel.
    ///
    /// Used for the channel the request already went to directly. Sending it
    /// twice and deduplicating the references afterwards still delivered two
    /// messages, which on a terminal meant being asked the same question twice.
    pub async fn broadcast_approval_except(
        &self,
        message: &OutboundMessage,
        skip: &ChannelId,
    ) -> Vec<ChannelMessageRef> {
        let mut delivered = Vec::new();
        for channel in self
            .channels
            .values()
            .filter(|c| c.can_approve() && &c.id() != skip)
        {
            let Some(target) = channel.default_target() else { continue };
            match channel.send(&target, message).await {
                Ok(reference) => delivered.push(reference),
                Err(e) => tracing::warn!(
                    channel = channel.name(),
                    error = %e,
                    "could not deliver approval request"
                ),
            }
        }
        delivered
    }

    /// Route a webhook to whichever channel claims it.
    pub async fn handle_webhook(
        &self,
        kind: ChannelKind,
        headers: &[(String, String)],
        body: &[u8],
    ) -> anyhow::Result<Vec<InboundMessage>> {
        let channel = self
            .by_kind(kind)
            .ok_or_else(|| anyhow::anyhow!("no {} channel is configured", kind))?;
        channel.handle_webhook(headers, body).await
    }

    pub fn verify_challenge(&self, kind: ChannelKind, query: &[(String, String)]) -> Option<String> {
        self.by_kind(kind)?.verify_challenge(query)
    }
}

/// Whether an action ID represents an authorization decision, as opposed to a
/// harmless interaction like expanding a plan's detail.
fn is_decision_action(message: &InboundMessage) -> bool {
    message
        .action
        .as_deref()
        .map(|action| {
            action.starts_with("approve") || action.starts_with("deny") || action.starts_with("confirm")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct Fake {
        id: ChannelId,
        kind: ChannelKind,
        allow: Vec<String>,
        can_approve: bool,
    }

    impl Fake {
        fn new(name: &str, kind: ChannelKind) -> Self {
            Self { id: ChannelId::derive(name), kind, allow: vec![], can_approve: true }
        }
        fn allowing(mut self, accounts: &[&str]) -> Self {
            self.allow = accounts.iter().map(|a| a.to_string()).collect();
            self
        }
        fn notify_only(mut self) -> Self {
            self.can_approve = false;
            self
        }
    }

    #[async_trait]
    impl Channel for Fake {
        fn kind(&self) -> ChannelKind {
            self.kind
        }
        fn id(&self) -> ChannelId {
            self.id.clone()
        }
        fn name(&self) -> &str {
            "fake"
        }
        fn can_approve(&self) -> bool {
            self.can_approve
        }
        fn is_allowed(&self, account_id: &str) -> bool {
            self.allow.iter().any(|a| a == account_id)
        }
        fn default_target(&self) -> Option<ChannelTarget> {
            Some(ChannelTarget::new(self.id.clone(), self.kind, "default"))
        }
        async fn run(
            self: Arc<Self>,
            _inbound: mpsc::Sender<InboundMessage>,
            cancel: CancellationToken,
        ) -> anyhow::Result<()> {
            cancel.cancelled().await;
            Ok(())
        }
        async fn send(
            &self,
            target: &ChannelTarget,
            _message: &OutboundMessage,
        ) -> anyhow::Result<ChannelMessageRef> {
            Ok(ChannelMessageRef { target: target.clone(), message_id: "m1".into() })
        }
        async fn update(
            &self,
            _reference: &ChannelMessageRef,
            _message: &OutboundMessage,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn message(channel: &Fake, sender: &str) -> InboundMessage {
        InboundMessage {
            target: ChannelTarget::new(channel.id.clone(), channel.kind, "conv"),
            sender_id: sender.into(),
            sender_name: sender.into(),
            operator: None,
            text: "hello".into(),
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: None,
            mentioned: false,
            direct: true,
            received_at: seep_proto::now_rfc3339(),
            raw: None,
        }
    }

    fn manager(channels: Vec<Fake>) -> ChannelManager {
        let mut manager = ChannelManager::new(true);
        for channel in channels {
            manager.register(Arc::new(channel));
        }
        manager
    }

    #[test]
    fn an_allowlisted_sender_is_admitted() {
        let channel = Fake::new("slack", ChannelKind::Slack).allowing(&["U1"]);
        let message = message(&channel, "U1");
        let manager = manager(vec![Fake::new("slack", ChannelKind::Slack).allowing(&["U1"])]);
        assert!(manager.admit(message).is_ok());
    }

    #[test]
    fn an_unknown_sender_is_rejected_before_reaching_the_agent() {
        // A stranger's message is data, never an instruction.
        let channel = Fake::new("slack", ChannelKind::Slack).allowing(&["U1"]);
        let message = message(&channel, "U-stranger");
        let manager = manager(vec![Fake::new("slack", ChannelKind::Slack).allowing(&["U1"])]);
        assert_eq!(
            manager.admit(message),
            Err(Rejection::UnknownSender {
                channel: ChannelKind::Slack,
                account: "U-stranger".into()
            })
        );
    }

    #[test]
    fn a_message_for_an_unregistered_channel_is_rejected() {
        let orphan = Fake::new("nowhere", ChannelKind::Discord).allowing(&["U1"]);
        let message = message(&orphan, "U1");
        let manager = manager(vec![Fake::new("slack", ChannelKind::Slack).allowing(&["U1"])]);
        assert!(manager.admit(message).is_err());
    }

    #[test]
    fn a_notify_only_channel_cannot_carry_an_approval() {
        // A public status channel must not become a place anyone can approve
        // a production change.
        let channel = Fake::new("status", ChannelKind::Slack)
            .allowing(&["U1"])
            .notify_only();
        let mut message = message(&channel, "U1");
        message.action = Some("approve:apr_x".into());

        let manager = manager(vec![Fake::new("status", ChannelKind::Slack)
            .allowing(&["U1"])
            .notify_only()]);
        assert_eq!(
            manager.admit(message),
            Err(Rejection::ApprovalNotPermitted { channel: ChannelKind::Slack })
        );
    }

    #[test]
    fn a_notify_only_channel_still_accepts_harmless_interactions() {
        let channel = Fake::new("status", ChannelKind::Slack)
            .allowing(&["U1"])
            .notify_only();
        let mut message = message(&channel, "U1");
        message.action = Some("expand_details".into());

        let manager = manager(vec![Fake::new("status", ChannelKind::Slack)
            .allowing(&["U1"])
            .notify_only()]);
        assert!(manager.admit(message).is_ok());
    }

    #[test]
    fn group_messages_without_a_mention_are_not_addressed_to_us() {
        let channel = Fake::new("slack", ChannelKind::Slack).allowing(&["U1"]);
        let mut message = message(&channel, "U1");
        message.direct = false;
        message.mentioned = false;

        let manager = manager(vec![Fake::new("slack", ChannelKind::Slack).allowing(&["U1"])]);
        assert_eq!(manager.admit(message), Err(Rejection::NotAddressed));
    }

    #[test]
    fn mention_requirements_can_be_relaxed() {
        let channel = Fake::new("slack", ChannelKind::Slack).allowing(&["U1"]);
        let mut message = message(&channel, "U1");
        message.direct = false;
        message.mentioned = false;

        let mut manager = ChannelManager::new(false);
        manager.register(Arc::new(Fake::new("slack", ChannelKind::Slack).allowing(&["U1"])));
        assert!(manager.admit(message).is_ok());
    }

    #[tokio::test]
    async fn broadcast_reaches_every_channel_with_a_default_target() {
        let manager = manager(vec![
            Fake::new("slack", ChannelKind::Slack),
            Fake::new("telegram", ChannelKind::Telegram),
        ]);
        let delivered = manager.broadcast(&OutboundMessage::text("incident opened")).await;
        assert_eq!(delivered.len(), 2);
    }

    #[tokio::test]
    async fn approval_broadcasts_skip_notify_only_channels() {
        let manager = manager(vec![
            Fake::new("slack", ChannelKind::Slack),
            Fake::new("status", ChannelKind::Telegram).notify_only(),
        ]);
        assert_eq!(manager.broadcast(&OutboundMessage::text("x")).await.len(), 2);
        assert_eq!(
            manager.broadcast_approval(&OutboundMessage::text("x")).await.len(),
            1
        );
    }

    #[test]
    fn channels_are_addressable_by_kind() {
        let manager = manager(vec![
            Fake::new("slack", ChannelKind::Slack),
            Fake::new("telegram", ChannelKind::Telegram),
        ]);
        assert!(manager.by_kind(ChannelKind::Slack).is_some());
        assert!(manager.by_kind(ChannelKind::Discord).is_none());
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn decision_actions_are_distinguished_from_harmless_ones() {
        let channel = Fake::new("slack", ChannelKind::Slack);
        let mut message = message(&channel, "U1");
        for action in ["approve:x", "deny:x", "confirm:x"] {
            message.action = Some(action.into());
            assert!(is_decision_action(&message), "{} should be a decision", action);
        }
        for action in ["expand", "show_plan", "mute"] {
            message.action = Some(action.into());
            assert!(!is_decision_action(&message), "{} should not be", action);
        }
    }
}
