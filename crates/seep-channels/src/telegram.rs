//! Telegram.
//!
//! Long polling rather than webhooks, deliberately: it needs no public URL, no
//! TLS certificate, and no inbound firewall rule, so a gateway on a laptop behind
//! NAT works exactly like one in a datacentre. That property is what makes
//! Telegram the fastest path from "installed SeeP" to "approving a production
//! change from my phone".

use async_trait::async_trait;
use seep_core::gateway::TelegramConfig;
use seep_proto::channel::{
    ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage, OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::render;
use crate::Channel;

pub struct TelegramChannel {
    id: ChannelId,
    config: TelegramConfig,
    http: reqwest::Client,
    /// Last update ID acknowledged, so a restart does not replay the backlog.
    offset: AtomicI64,
}

impl TelegramChannel {
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            id: ChannelId::derive("telegram"),
            config,
            http: reqwest::Client::builder()
                // Comfortably longer than the long-poll timeout below.
                .timeout(Duration::from_secs(75))
                .build()
                .unwrap_or_default(),
            offset: AtomicI64::new(0),
        }
    }

    fn api(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.config.bot_token, method)
    }

    /// Fetch the next batch of updates.
    async fn poll(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let offset = self.offset.load(Ordering::Relaxed);
        let response = self
            .http
            .post(self.api("getUpdates"))
            .json(&serde_json::json!({
                "offset": offset,
                // Long poll: the request hangs until something happens, so
                // messages arrive promptly without hammering the API.
                "timeout": 50,
                "allowed_updates": ["message", "callback_query"],
            }))
            .send()
            .await?;

        let value: serde_json::Value = response.json().await?;
        if !value["ok"].as_bool().unwrap_or(false) {
            anyhow::bail!(
                "telegram getUpdates failed: {}",
                value["description"].as_str().unwrap_or("unknown error")
            );
        }
        let updates = value["result"].as_array().cloned().unwrap_or_default();
        if let Some(last) = updates.last() {
            if let Some(id) = last["update_id"].as_i64() {
                // Acknowledge through this update so it is not delivered again.
                self.offset.store(id + 1, Ordering::Relaxed);
            }
        }
        Ok(updates)
    }

    /// Convert a raw update into an inbound message.
    pub fn parse_update(&self, update: &serde_json::Value) -> Option<InboundMessage> {
        if let Some(callback) = update.get("callback_query").filter(|v| !v.is_null()) {
            return self.parse_callback(callback);
        }
        let message = update.get("message").filter(|v| !v.is_null())?;
        let chat = &message["chat"];
        let chat_id = chat["id"].as_i64()?.to_string();
        let from = &message["from"];
        let sender_id = from["id"].as_i64()?.to_string();
        let text = message["text"].as_str().unwrap_or_default().to_string();
        if text.trim().is_empty() {
            return None;
        }

        let is_private = chat["type"].as_str() == Some("private");
        let mentioned = text.contains("@") && text.to_lowercase().contains("seep");

        Some(InboundMessage {
            target: ChannelTarget::new(self.id.clone(), ChannelKind::Telegram, chat_id),
            sender_id,
            sender_name: from["username"]
                .as_str()
                .or_else(|| from["first_name"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            operator: None,
            text,
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: message["message_id"].as_i64().map(|v| v.to_string()),
            mentioned,
            direct: is_private,
            received_at: seep_proto::now_rfc3339(),
            raw: Some(update.clone()),
        })
    }

    fn parse_callback(&self, callback: &serde_json::Value) -> Option<InboundMessage> {
        let from = &callback["from"];
        let message = &callback["message"];
        let chat_id = message["chat"]["id"].as_i64()?.to_string();
        Some(InboundMessage {
            target: ChannelTarget::new(self.id.clone(), ChannelKind::Telegram, chat_id),
            sender_id: from["id"].as_i64()?.to_string(),
            sender_name: from["username"].as_str().unwrap_or("unknown").to_string(),
            operator: None,
            text: String::new(),
            attachments: vec![],
            action: callback["data"].as_str().map(|s| s.to_string()),
            interaction_token: callback["id"].as_str().map(|s| s.to_string()),
            source_message_id: message["message_id"].as_i64().map(|v| v.to_string()),
            mentioned: true,
            direct: message["chat"]["type"].as_str() == Some("private"),
            received_at: seep_proto::now_rfc3339(),
            raw: Some(callback.clone()),
        })
    }

    /// Build the inline keyboard for a message's actions.
    pub fn keyboard(message: &OutboundMessage) -> Option<serde_json::Value> {
        if message.actions.is_empty() {
            return None;
        }
        // One button per row: on a phone, two side-by-side buttons where one
        // approves a production change and the other denies it is a mis-tap
        // waiting to happen.
        let rows: Vec<serde_json::Value> = message
            .actions
            .iter()
            .map(|action| {
                serde_json::json!([{
                    "text": match action.style.as_str() {
                        "danger" => format!("⚠ {}", action.label),
                        "primary" => format!("✓ {}", action.label),
                        _ => action.label.clone(),
                    },
                    "callback_data": action.id,
                }])
            })
            .collect();
        Some(serde_json::json!({ "inline_keyboard": rows }))
    }
}

#[async_trait]
impl Channel for TelegramChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Telegram
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "telegram"
    }

    fn can_approve(&self) -> bool {
        self.config.can_approve
    }

    fn is_allowed(&self, account_id: &str) -> bool {
        // An empty allowlist means nobody, never everybody.
        self.config.allow_from.iter().any(|a| a == account_id)
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        if self.config.default_chat_id.is_empty() {
            return None;
        }
        Some(ChannelTarget::new(
            self.id.clone(),
            ChannelKind::Telegram,
            self.config.default_chat_id.clone(),
        ))
    }

    async fn run(
        self: Arc<Self>,
        inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        tracing::info!("telegram channel started");
        let mut backoff = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("telegram channel stopping");
                    return Ok(());
                }
                result = self.poll() => match result {
                    Ok(updates) => {
                        backoff = Duration::from_secs(1);
                        for update in updates {
                            if let Some(message) = self.parse_update(&update) {
                                if inbound.send(message).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Back off rather than spinning: a revoked token would
                        // otherwise produce thousands of failed calls a minute.
                        tracing::warn!(error = %e, backoff = ?backoff, "telegram poll failed");
                        tokio::select! {
                            _ = cancel.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                }
            }
        }
    }

    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let parts = render::split_for(ChannelKind::Telegram, message);
        let mut last_id = String::new();

        for part in &parts {
            let mut body = serde_json::json!({
                "chat_id": target.conversation,
                "text": render::to_markdown(part),
                "parse_mode": "Markdown",
                "disable_notification": part.silent,
            });
            if let Some(keyboard) = Self::keyboard(part) {
                body["reply_markup"] = keyboard;
            }

            let response: serde_json::Value = self
                .http
                .post(self.api("sendMessage"))
                .json(&body)
                .send()
                .await?
                .json()
                .await?;

            if !response["ok"].as_bool().unwrap_or(false) {
                // Markdown parsing is the usual culprit — an unbalanced asterisk
                // in a log excerpt. Retry as plain text rather than losing the
                // message entirely, because the content matters more than the styling.
                let plain = serde_json::json!({
                    "chat_id": target.conversation,
                    "text": render::to_plain_text(part),
                    "disable_notification": part.silent,
                });
                let retry: serde_json::Value = self
                    .http
                    .post(self.api("sendMessage"))
                    .json(&plain)
                    .send()
                    .await?
                    .json()
                    .await?;
                anyhow::ensure!(
                    retry["ok"].as_bool().unwrap_or(false),
                    "telegram sendMessage failed: {}",
                    retry["description"].as_str().unwrap_or("unknown error")
                );
                last_id = retry["result"]["message_id"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                continue;
            }
            last_id = response["result"]["message_id"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_default();
        }

        Ok(ChannelMessageRef { target: target.clone(), message_id: last_id })
    }

    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        let mut body = serde_json::json!({
            "chat_id": reference.target.conversation,
            "message_id": reference.message_id.parse::<i64>().unwrap_or_default(),
            "text": render::to_markdown(message),
            "parse_mode": "Markdown",
        });
        // Sending an empty keyboard removes the buttons, which is exactly what a
        // decided approval needs.
        body["reply_markup"] = Self::keyboard(message)
            .unwrap_or_else(|| serde_json::json!({ "inline_keyboard": [] }));

        self.http.post(self.api("editMessageText")).json(&body).send().await?;
        Ok(())
    }

    async fn acknowledge(&self, message: &InboundMessage) -> anyhow::Result<()> {
        let Some(token) = &message.interaction_token else { return Ok(()) };
        // Without this the button keeps spinning on the operator's phone.
        self.http
            .post(self.api("answerCallbackQuery"))
            .json(&serde_json::json!({ "callback_query_id": token }))
            .send()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn channel(allow: &[&str]) -> TelegramChannel {
        TelegramChannel::new(TelegramConfig {
            enabled: true,
            bot_token: "test-token".into(),
            allow_from: allow.iter().map(|a| a.to_string()).collect(),
            default_chat_id: "12345".into(),
            can_approve: true,
        })
    }

    #[test]
    fn an_empty_allowlist_admits_nobody() {
        // The default posture: an unconfigured bot is not an open one.
        let channel = channel(&[]);
        assert!(!channel.is_allowed("12345"));
        assert!(!channel.is_allowed("anyone"));
    }

    #[test]
    fn only_listed_accounts_are_allowed() {
        let channel = channel(&["111", "222"]);
        assert!(channel.is_allowed("111"));
        assert!(channel.is_allowed("222"));
        assert!(!channel.is_allowed("333"));
    }

    #[test]
    fn a_text_message_parses() {
        let channel = channel(&["111"]);
        let update = serde_json::json!({
            "update_id": 1,
            "message": {
                "message_id": 42,
                "chat": { "id": 12345, "type": "private" },
                "from": { "id": 111, "username": "alice" },
                "text": "why is nginx down"
            }
        });
        let parsed = channel.parse_update(&update).unwrap();
        assert_eq!(parsed.sender_id, "111");
        assert_eq!(parsed.sender_name, "alice");
        assert_eq!(parsed.text, "why is nginx down");
        assert_eq!(parsed.target.conversation, "12345");
        assert!(parsed.direct);
        assert!(parsed.action.is_none());
    }

    #[test]
    fn a_group_message_is_not_marked_direct() {
        let channel = channel(&["111"]);
        let update = serde_json::json!({
            "update_id": 1,
            "message": {
                "message_id": 42,
                "chat": { "id": -100, "type": "group" },
                "from": { "id": 111, "username": "alice" },
                "text": "hello everyone"
            }
        });
        let parsed = channel.parse_update(&update).unwrap();
        assert!(!parsed.direct);
        assert!(!parsed.mentioned);
        assert!(!parsed.should_handle(true), "group chatter is ignored without a mention");
    }

    #[test]
    fn a_button_press_parses_as_an_action() {
        let channel = channel(&["111"]);
        let update = serde_json::json!({
            "update_id": 2,
            "callback_query": {
                "id": "cb-1",
                "from": { "id": 111, "username": "alice" },
                "data": "approve:apr_abc123",
                "message": {
                    "message_id": 42,
                    "chat": { "id": 12345, "type": "private" }
                }
            }
        });
        let parsed = channel.parse_update(&update).unwrap();
        assert_eq!(parsed.action.as_deref(), Some("approve:apr_abc123"));
        assert_eq!(parsed.interaction_token.as_deref(), Some("cb-1"));
        assert!(parsed.should_handle(true), "a button press is always for us");
    }

    #[test]
    fn empty_and_non_message_updates_are_skipped() {
        let channel = channel(&["111"]);
        assert!(channel.parse_update(&serde_json::json!({ "update_id": 1 })).is_none());
        assert!(channel
            .parse_update(&serde_json::json!({
                "update_id": 1,
                "message": {
                    "message_id": 1,
                    "chat": { "id": 1, "type": "private" },
                    "from": { "id": 1 },
                    "text": "   "
                }
            }))
            .is_none());
    }

    #[test]
    fn approval_buttons_are_one_per_row() {
        // Side-by-side approve and deny on a phone is a mis-tap waiting to happen.
        let message = OutboundMessage::text("approve this?").with_actions(vec![
            PresentedAction::primary("approve", "Approve"),
            PresentedAction::danger("deny", "Deny"),
        ]);
        let keyboard = TelegramChannel::keyboard(&message).unwrap();
        let rows = keyboard["inline_keyboard"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].as_array().unwrap().len(), 1);
        assert!(rows[1][0]["text"].as_str().unwrap().contains("Deny"));
    }

    #[test]
    fn a_message_without_actions_has_no_keyboard() {
        assert!(TelegramChannel::keyboard(&OutboundMessage::text("hello")).is_none());
    }

    #[test]
    fn the_default_target_is_absent_when_unconfigured() {
        let config = TelegramConfig { default_chat_id: String::new(), ..Default::default() };
        assert!(TelegramChannel::new(config).default_target().is_none());
        assert!(channel(&[]).default_target().is_some());
    }

    #[test]
    fn approval_capability_follows_configuration() {
        let config = TelegramConfig { can_approve: false, ..Default::default() };
        assert!(!TelegramChannel::new(config).can_approve());
        assert!(channel(&[]).can_approve());
    }
}
