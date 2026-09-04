//! Channel-agnostic messaging types.
//!
//! Telegram, Slack, Discord, WhatsApp and the built-in web chat all differ wildly
//! in their APIs, but the gateway only ever deals in the types below. An adapter's
//! job is to translate, and nothing above it should ever know which platform a
//! message came from — except where that fact is evidence, as in an approval.

use crate::ids::{ChannelId, OperatorId, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    Cli,
    Web,
    Telegram,
    Slack,
    Discord,
    WhatsApp,
    /// An automated trigger (webhook, schedule) rather than a person.
    System,
}

impl ChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelKind::Cli => "cli",
            ChannelKind::Web => "web",
            ChannelKind::Telegram => "telegram",
            ChannelKind::Slack => "slack",
            ChannelKind::Discord => "discord",
            ChannelKind::WhatsApp => "whatsapp",
            ChannelKind::System => "system",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "cli" => ChannelKind::Cli,
            "web" | "webchat" => ChannelKind::Web,
            "telegram" | "tg" => ChannelKind::Telegram,
            "slack" => ChannelKind::Slack,
            "discord" => ChannelKind::Discord,
            "whatsapp" | "wa" => ChannelKind::WhatsApp,
            "system" => ChannelKind::System,
            _ => return None,
        })
    }

    /// Whether the platform can render tappable buttons. Adapters that cannot
    /// fall back to reply-with-a-word approval, which still works but reads worse.
    pub fn supports_buttons(&self) -> bool {
        matches!(
            self,
            ChannelKind::Web
                | ChannelKind::Telegram
                | ChannelKind::Slack
                | ChannelKind::Discord
                | ChannelKind::WhatsApp
        )
    }

    /// Whether messages can be edited in place after sending. Where true, an
    /// approval card is rewritten once decided rather than left showing live
    /// buttons for an action that already happened.
    pub fn supports_edit(&self) -> bool {
        matches!(
            self,
            ChannelKind::Web | ChannelKind::Telegram | ChannelKind::Slack | ChannelKind::Discord
        )
    }

    /// Whether replies can be threaded under a parent message.
    pub fn supports_threads(&self) -> bool {
        matches!(self, ChannelKind::Slack | ChannelKind::Discord | ChannelKind::Web)
    }

    /// Practical per-message character budget. Long outputs are chunked or
    /// attached as files rather than truncated silently.
    pub fn max_message_chars(&self) -> usize {
        match self {
            ChannelKind::Telegram => 4096,
            ChannelKind::Slack => 3000,
            ChannelKind::Discord => 2000,
            ChannelKind::WhatsApp => 4096,
            ChannelKind::Web | ChannelKind::Cli | ChannelKind::System => 100_000,
        }
    }
}

impl std::fmt::Display for ChannelKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A configured channel instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDescriptor {
    pub id: ChannelId,
    pub kind: ChannelKind,
    /// Operator-facing name, e.g. "ops-alerts".
    pub name: String,
    pub enabled: bool,
    /// Whether this channel is allowed to *authorize* actions, as opposed to
    /// merely receiving notifications. A public status channel should not be an
    /// approval surface.
    #[serde(default)]
    pub can_approve: bool,
    /// Where unsolicited notifications go on this platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_target: Option<ChannelTarget>,
    #[serde(default)]
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Where to deliver a message on a given platform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelTarget {
    pub channel_id: ChannelId,
    pub kind: ChannelKind,
    /// Platform-native conversation identifier (chat ID, channel ID, JID).
    pub conversation: String,
    /// Thread to reply within, where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
}

impl ChannelTarget {
    pub fn new(channel_id: ChannelId, kind: ChannelKind, conversation: impl Into<String>) -> Self {
        Self { channel_id, kind, conversation: conversation.into(), thread: None }
    }

    pub fn in_thread(mut self, thread: impl Into<String>) -> Self {
        self.thread = Some(thread.into());
        self
    }
}

/// A pointer to a message that was actually delivered, so it can be edited later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMessageRef {
    pub target: ChannelTarget,
    pub message_id: String,
}

/// A message arriving from a human.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboundMessage {
    pub target: ChannelTarget,
    /// Platform-native sender identifier.
    pub sender_id: String,
    /// Display name, best effort.
    #[serde(default)]
    pub sender_name: String,
    /// The SeeP operator this message speaks for, when the transport has already
    /// established that.
    ///
    /// Set by transports that authenticate before the message exists — the HTTP
    /// API and its socket, where a credential named the caller — and left `None`
    /// by chat platforms, whose accounts are resolved against the registry
    /// instead. `None` means the sender is unrecognised so far, and the gateway
    /// must treat the message as untrusted input rather than as an instruction.
    ///
    /// A claim here is still checked: the gateway confirms the operator exists
    /// and is enabled before acting on it. What it saves is the *binding*
    /// lookup, which is meaningless for a transport that has no platform account
    /// to bind — nobody has a Slack ID for their own terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<OperatorId>,
    pub text: String,
    #[serde(default)]
    pub attachments: Vec<MessageAttachment>,
    /// Set when the human tapped a button rather than typing. Carries the
    /// action ID the gateway originally attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Platform identifier for the interaction, needed to acknowledge it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_token: Option<String>,
    /// The message the action was attached to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_message_id: Option<String>,
    /// Whether the bot was explicitly addressed. In group conversations the
    /// gateway ignores messages that are not, so it does not barge into every
    /// thread it can see.
    #[serde(default)]
    pub mentioned: bool,
    /// True when the conversation is one-to-one.
    #[serde(default)]
    pub direct: bool,
    pub received_at: String,
    /// Raw platform payload, retained as evidence for approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl InboundMessage {
    /// Whether the gateway should respond. Group messages need an explicit
    /// mention; direct messages and button presses always count.
    pub fn should_handle(&self, require_mention_in_groups: bool) -> bool {
        if self.action.is_some() {
            return true;
        }
        if self.direct {
            return true;
        }
        !require_mention_in_groups || self.mentioned
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageAttachment {
    pub name: String,
    pub mime_type: String,
    /// Either a platform URL the adapter can fetch, or inline base64 content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
    pub size_bytes: u64,
}

/// A tappable action rendered alongside a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresentedAction {
    /// Opaque ID echoed back when tapped.
    pub id: String,
    pub label: String,
    /// `primary`, `danger`, or `secondary`. Adapters map this to native styling;
    /// destructive approvals render red on every platform that has the concept.
    #[serde(default)]
    pub style: String,
}

impl PresentedAction {
    pub fn primary(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), label: label.into(), style: "primary".into() }
    }
    pub fn danger(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), label: label.into(), style: "danger".into() }
    }
    pub fn secondary(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), label: label.into(), style: "secondary".into() }
    }
}

/// A message the gateway wants to deliver.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub text: String,
    /// Optional bold heading rendered above the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Preformatted block appended below the body — command output, diffs, logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_block: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<PresentedAction>,
    /// Accent colour hint: `info`, `success`, `warning`, `danger`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<MessageAttachment>,
    /// Session this message belongs to, for threading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Suppress push notifications for routine progress updates.
    #[serde(default)]
    pub silent: bool,
}

impl OutboundMessage {
    pub fn text(text: impl Into<String>) -> Self {
        Self { text: text.into(), ..Default::default() }
    }

    pub fn titled(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self { title: Some(title.into()), text: text.into(), ..Default::default() }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code_block = Some(code.into());
        self
    }

    pub fn with_actions(mut self, actions: Vec<PresentedAction>) -> Self {
        self.actions = actions;
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    /// Split into platform-sized pieces, never mid-line where avoidable.
    ///
    /// Chunking rather than truncating matters: an operator deciding whether to
    /// approve something must not be shown a plan whose tail was silently cut off.
    pub fn split_text(text: &str, limit: usize) -> Vec<String> {
        if text.chars().count() <= limit {
            return vec![text.to_string()];
        }
        let mut chunks = Vec::new();
        let mut current = String::new();
        for line in text.split_inclusive('\n') {
            if line.chars().count() > limit {
                // A single line longer than the limit has to be hard-split.
                if !current.is_empty() {
                    chunks.push(std::mem::take(&mut current));
                }
                let mut buffer = String::new();
                for ch in line.chars() {
                    if buffer.chars().count() + 1 > limit {
                        chunks.push(std::mem::take(&mut buffer));
                    }
                    buffer.push(ch);
                }
                current = buffer;
                continue;
            }
            if current.chars().count() + line.chars().count() > limit {
                chunks.push(std::mem::take(&mut current));
            }
            current.push_str(line);
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_messages_need_a_mention() {
        let base = InboundMessage {
            target: ChannelTarget::new(ChannelId::generate(), ChannelKind::Slack, "C1"),
            sender_id: "U1".into(),
            sender_name: "alice".into(),
            operator: None,
            text: "hey".into(),
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: None,
            mentioned: false,
            direct: false,
            received_at: crate::now_rfc3339(),
            raw: None,
        };
        assert!(!base.should_handle(true));

        let mentioned = InboundMessage { mentioned: true, ..base.clone() };
        assert!(mentioned.should_handle(true));

        let dm = InboundMessage { direct: true, ..base.clone() };
        assert!(dm.should_handle(true));

        // A button press is always meant for us, mention or not.
        let tapped = InboundMessage { action: Some("approve".into()), ..base };
        assert!(tapped.should_handle(true));
    }

    #[test]
    fn short_text_is_not_split() {
        assert_eq!(OutboundMessage::split_text("hello", 100), vec!["hello"]);
    }

    #[test]
    fn splitting_preserves_every_character() {
        let text = (0..200).map(|i| format!("line {}\n", i)).collect::<String>();
        let chunks = OutboundMessage::split_text(&text, 300);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|c| c.chars().count() <= 300));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn a_single_overlong_line_is_hard_split_without_loss() {
        let text = "x".repeat(1000);
        let chunks = OutboundMessage::split_text(&text, 100);
        assert_eq!(chunks.len(), 10);
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn channel_kind_round_trips() {
        for kind in [
            ChannelKind::Cli,
            ChannelKind::Web,
            ChannelKind::Telegram,
            ChannelKind::Slack,
            ChannelKind::Discord,
            ChannelKind::WhatsApp,
            ChannelKind::System,
        ] {
            assert_eq!(ChannelKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn message_limits_are_below_platform_maximums() {
        assert!(ChannelKind::Discord.max_message_chars() <= 2000);
        assert!(ChannelKind::Telegram.max_message_chars() <= 4096);
    }
}
