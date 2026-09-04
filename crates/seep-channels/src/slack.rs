//! Slack, over Socket Mode.
//!
//! Socket Mode rather than the Events API: the gateway dials out to Slack, so it
//! needs no public URL and no request-signing endpoint. For a tool that will
//! often run inside the network it manages, that is the difference between a
//! five-minute setup and an ingress ticket.
//!
//! Approval cards use Block Kit so the buttons are real buttons, and the card is
//! rewritten in place once decided rather than left showing live controls for a
//! decision already made.

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use seep_core::gateway::SlackConfig;
use seep_proto::channel::{
    ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage, OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::render;
use crate::Channel;

pub struct SlackChannel {
    id: ChannelId,
    config: SlackConfig,
    http: reqwest::Client,
    /// The bot's own user ID, learned at connect time so its own messages can be
    /// ignored — otherwise the agent replies to itself, forever.
    bot_user_id: tokio::sync::RwLock<Option<String>>,
}

impl SlackChannel {
    pub fn new(config: SlackConfig) -> Self {
        Self {
            id: ChannelId::derive("slack"),
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            bot_user_id: tokio::sync::RwLock::new(None),
        }
    }

    async fn api(&self, method: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let response: serde_json::Value = self
            .http
            .post(format!("https://slack.com/api/{}", method))
            .bearer_auth(&self.config.bot_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !response["ok"].as_bool().unwrap_or(false) {
            anyhow::bail!(
                "slack {} failed: {}",
                method,
                response["error"].as_str().unwrap_or("unknown error")
            );
        }
        Ok(response)
    }

    /// Open a Socket Mode connection and return its one-time WebSocket URL.
    async fn open_socket(&self) -> anyhow::Result<String> {
        let response: serde_json::Value = self
            .http
            .post("https://slack.com/api/apps.connections.open")
            .bearer_auth(&self.config.app_token)
            .send()
            .await?
            .json()
            .await?;
        if !response["ok"].as_bool().unwrap_or(false) {
            anyhow::bail!(
                "slack apps.connections.open failed: {}",
                response["error"].as_str().unwrap_or("unknown error")
            );
        }
        response["url"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("slack did not return a socket url"))
    }

    async fn learn_own_identity(&self) {
        if let Ok(response) = self.api("auth.test", serde_json::json!({})).await {
            if let Some(id) = response["user_id"].as_str() {
                *self.bot_user_id.write().await = Some(id.to_string());
            }
        }
    }

    /// Parse a Socket Mode envelope into an inbound message.
    pub async fn parse_envelope(&self, envelope: &serde_json::Value) -> Option<InboundMessage> {
        match envelope["type"].as_str()? {
            "events_api" => self.parse_event(&envelope["payload"]).await,
            "interactive" => self.parse_interaction(&envelope["payload"]),
            _ => None,
        }
    }

    async fn parse_event(&self, payload: &serde_json::Value) -> Option<InboundMessage> {
        let event = &payload["event"];
        let kind = event["type"].as_str()?;
        if kind != "message" && kind != "app_mention" {
            return None;
        }
        // Slack echoes the bot's own messages back. Without this the agent would
        // answer itself in an endless loop.
        if event.get("bot_id").is_some() || event["subtype"].as_str() == Some("bot_message") {
            return None;
        }
        let user = event["user"].as_str()?;
        if let Some(own) = self.bot_user_id.read().await.as_deref() {
            if user == own {
                return None;
            }
        }

        let channel = event["channel"].as_str()?.to_string();
        let text = event["text"].as_str().unwrap_or_default().to_string();
        if text.trim().is_empty() {
            return None;
        }

        let mentioned = kind == "app_mention"
            || self
                .bot_user_id
                .read()
                .await
                .as_deref()
                .map(|id| text.contains(&format!("<@{}>", id)))
                .unwrap_or(false);

        let mut target = ChannelTarget::new(self.id.clone(), ChannelKind::Slack, channel.clone());
        // Reply in the thread when there is one, so an incident conversation
        // stays in one place instead of scattering through the channel.
        if let Some(thread) = event["thread_ts"].as_str() {
            target = target.in_thread(thread);
        }

        Some(InboundMessage {
            target,
            sender_id: user.to_string(),
            sender_name: event["user_profile"]["display_name"]
                .as_str()
                .unwrap_or(user)
                .to_string(),
            operator: None,
            text,
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: event["ts"].as_str().map(|s| s.to_string()),
            mentioned,
            // A `D`-prefixed channel ID is a direct message.
            direct: channel.starts_with('D'),
            received_at: seep_proto::now_rfc3339(),
            raw: Some(payload.clone()),
        })
    }

    fn parse_interaction(&self, payload: &serde_json::Value) -> Option<InboundMessage> {
        let action = payload["actions"].as_array()?.first()?;
        let user = payload["user"]["id"].as_str()?;
        let channel = payload["channel"]["id"].as_str().unwrap_or_default().to_string();

        Some(InboundMessage {
            target: ChannelTarget::new(self.id.clone(), ChannelKind::Slack, channel.clone()),
            sender_id: user.to_string(),
            sender_name: payload["user"]["username"].as_str().unwrap_or(user).to_string(),
            operator: None,
            text: String::new(),
            attachments: vec![],
            action: action["value"]
                .as_str()
                .or_else(|| action["action_id"].as_str())
                .map(|s| s.to_string()),
            interaction_token: payload["response_url"].as_str().map(|s| s.to_string()),
            source_message_id: payload["message"]["ts"].as_str().map(|s| s.to_string()),
            mentioned: true,
            direct: channel.starts_with('D'),
            received_at: seep_proto::now_rfc3339(),
            raw: Some(payload.clone()),
        })
    }

    /// Render a message as Block Kit.
    pub fn blocks(message: &OutboundMessage) -> Vec<serde_json::Value> {
        let mut blocks = Vec::new();

        if let Some(title) = &message.title {
            blocks.push(serde_json::json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} {}", render::severity_icon(message.severity.as_deref()), title),
                    "emoji": true
                }
            }));
        }

        if !message.text.trim().is_empty() {
            blocks.push(serde_json::json!({
                "type": "section",
                // Slack truncates a section above 3000 characters, so it is cut
                // here where the boundary can be chosen rather than by Slack.
                "text": { "type": "mrkdwn", "text": clamp(&message.text, 2_900) }
            }));
        }

        if let Some(code) = &message.code_block {
            if !code.trim().is_empty() {
                blocks.push(serde_json::json!({
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": render::fence(code, 2_800) }
                }));
            }
        }

        if !message.actions.is_empty() {
            blocks.push(serde_json::json!({
                "type": "actions",
                "elements": message.actions.iter().map(|action| {
                    let mut element = serde_json::json!({
                        "type": "button",
                        "text": { "type": "plain_text", "text": action.label, "emoji": true },
                        "action_id": action.id,
                        "value": action.id,
                    });
                    match action.style.as_str() {
                        // Slack renders a `danger` button red and asks for
                        // confirmation, which is exactly right for a denial or a
                        // destructive approval.
                        "danger" => { element["style"] = serde_json::json!("danger"); }
                        "primary" => { element["style"] = serde_json::json!("primary"); }
                        _ => {}
                    }
                    element
                }).collect::<Vec<_>>()
            }));
        }

        blocks
    }
}

fn clamp(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit.saturating_sub(3)).collect();
    format!("{}…", kept)
}

#[async_trait]
impl Channel for SlackChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Slack
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "slack"
    }

    fn can_approve(&self) -> bool {
        self.config.can_approve
    }

    fn is_allowed(&self, account_id: &str) -> bool {
        self.config.allow_from.iter().any(|a| a == account_id)
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        if self.config.default_channel.is_empty() {
            return None;
        }
        Some(ChannelTarget::new(
            self.id.clone(),
            ChannelKind::Slack,
            self.config.default_channel.clone(),
        ))
    }

    async fn run(
        self: Arc<Self>,
        inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        self.learn_own_identity().await;
        let mut backoff = Duration::from_secs(1);

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }

            let url = match self.open_socket().await {
                Ok(url) => url,
                Err(e) => {
                    tracing::warn!(error = %e, "slack socket open failed");
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                    continue;
                }
            };

            match tokio_tungstenite::connect_async(&url).await {
                Ok((mut socket, _)) => {
                    tracing::info!("slack socket mode connected");
                    backoff = Duration::from_secs(1);

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                let _ = socket.close(None).await;
                                return Ok(());
                            }
                            frame = socket.next() => {
                                let Some(Ok(frame)) = frame else { break };
                                let tokio_tungstenite::tungstenite::Message::Text(text) = frame else {
                                    continue;
                                };
                                let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&text) else {
                                    continue;
                                };

                                // Acknowledge immediately. Slack re-delivers
                                // anything unacknowledged within three seconds,
                                // and a slow agent turn would otherwise cause
                                // the same request to be handled repeatedly.
                                if let Some(envelope_id) = envelope["envelope_id"].as_str() {
                                    let ack = serde_json::json!({ "envelope_id": envelope_id });
                                    let _ = socket
                                        .send(tokio_tungstenite::tungstenite::Message::Text(
                                            ack.to_string(),
                                        ))
                                        .await;
                                }

                                if envelope["type"].as_str() == Some("disconnect") {
                                    tracing::info!("slack asked us to reconnect");
                                    break;
                                }

                                if let Some(message) = self.parse_envelope(&envelope).await {
                                    if inbound.send(message).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "slack websocket connect failed");
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                }
            }
        }
    }

    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let mut body = serde_json::json!({
            "channel": target.conversation,
            "text": clamp(&render::to_plain_text(message), 2_900),
            "blocks": Self::blocks(message),
        });
        if let Some(thread) = &target.thread {
            body["thread_ts"] = serde_json::json!(thread);
        }

        let response = self.api("chat.postMessage", body).await?;
        Ok(ChannelMessageRef {
            target: target.clone(),
            message_id: response["ts"].as_str().unwrap_or_default().to_string(),
        })
    }

    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        self.api(
            "chat.update",
            serde_json::json!({
                "channel": reference.target.conversation,
                "ts": reference.message_id,
                "text": clamp(&render::to_plain_text(message), 2_900),
                "blocks": Self::blocks(message),
            }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn channel(allow: &[&str]) -> SlackChannel {
        SlackChannel::new(SlackConfig {
            enabled: true,
            app_token: "xapp-test".into(),
            bot_token: "xoxb-test".into(),
            allow_from: allow.iter().map(|a| a.to_string()).collect(),
            default_channel: "C123".into(),
            can_approve: true,
        })
    }

    #[test]
    fn an_empty_allowlist_admits_nobody() {
        assert!(!channel(&[]).is_allowed("U123"));
    }

    #[tokio::test]
    async fn a_channel_message_parses() {
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "envelope_id": "env-1",
            "payload": {
                "event": {
                    "type": "message",
                    "user": "U123",
                    "channel": "C999",
                    "text": "is the api healthy",
                    "ts": "1700000000.000100"
                }
            }
        });
        let parsed = channel.parse_envelope(&envelope).await.unwrap();
        assert_eq!(parsed.sender_id, "U123");
        assert_eq!(parsed.text, "is the api healthy");
        assert_eq!(parsed.target.conversation, "C999");
        assert!(!parsed.direct);
    }

    #[tokio::test]
    async fn a_direct_message_is_recognised_from_the_channel_prefix() {
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "payload": { "event": {
                "type": "message", "user": "U123", "channel": "D456", "text": "hi", "ts": "1"
            }}
        });
        let parsed = channel.parse_envelope(&envelope).await.unwrap();
        assert!(parsed.direct);
        assert!(parsed.should_handle(true));
    }

    #[tokio::test]
    async fn the_bots_own_messages_are_ignored() {
        // Without this the agent answers itself in an endless loop.
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "payload": { "event": {
                "type": "message", "user": "UBOT", "bot_id": "B1",
                "channel": "C1", "text": "my own reply", "ts": "1"
            }}
        });
        assert!(channel.parse_envelope(&envelope).await.is_none());
    }

    #[tokio::test]
    async fn bot_subtype_messages_are_ignored() {
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "payload": { "event": {
                "type": "message", "subtype": "bot_message", "user": "U1",
                "channel": "C1", "text": "posted by an integration", "ts": "1"
            }}
        });
        assert!(channel.parse_envelope(&envelope).await.is_none());
    }

    #[tokio::test]
    async fn an_app_mention_counts_as_being_addressed() {
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "payload": { "event": {
                "type": "app_mention", "user": "U123", "channel": "C1",
                "text": "<@UBOT> restart nginx", "ts": "1"
            }}
        });
        let parsed = channel.parse_envelope(&envelope).await.unwrap();
        assert!(parsed.mentioned);
        assert!(parsed.should_handle(true));
    }

    #[tokio::test]
    async fn thread_replies_stay_in_their_thread() {
        // An incident conversation should not scatter through the channel.
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "events_api",
            "payload": { "event": {
                "type": "message", "user": "U123", "channel": "C1",
                "text": "and what about disk", "ts": "2", "thread_ts": "1700000000.000100"
            }}
        });
        let parsed = channel.parse_envelope(&envelope).await.unwrap();
        assert_eq!(parsed.target.thread.as_deref(), Some("1700000000.000100"));
    }

    #[tokio::test]
    async fn a_button_press_parses_as_an_action() {
        let channel = channel(&["U123"]);
        let envelope = serde_json::json!({
            "type": "interactive",
            "payload": {
                "user": { "id": "U123", "username": "alice" },
                "channel": { "id": "C1" },
                "actions": [{ "action_id": "approve", "value": "approve:apr_abc" }],
                "response_url": "https://hooks.slack.com/x",
                "message": { "ts": "1700000000.000100" }
            }
        });
        let parsed = channel.parse_envelope(&envelope).await.unwrap();
        assert_eq!(parsed.action.as_deref(), Some("approve:apr_abc"));
        assert!(parsed.should_handle(true));
    }

    #[test]
    fn block_kit_renders_header_body_and_buttons() {
        let message = OutboundMessage::titled("Approval required", "restart nginx on web-01")
            .with_actions(vec![
                PresentedAction::primary("approve", "Approve"),
                PresentedAction::danger("deny", "Deny"),
            ]);
        let blocks = SlackChannel::blocks(&message);

        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
        let actions = blocks.last().unwrap();
        assert_eq!(actions["type"], "actions");
        assert_eq!(actions["elements"].as_array().unwrap().len(), 2);
        assert_eq!(actions["elements"][1]["style"], "danger");
    }

    #[test]
    fn oversized_sections_are_cut_where_we_choose() {
        // Slack would otherwise truncate mid-word at an arbitrary point.
        let message = OutboundMessage::text("x".repeat(10_000));
        let blocks = SlackChannel::blocks(&message);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(text.chars().count() <= 2_900);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn a_message_with_no_actions_renders_no_action_block() {
        let blocks = SlackChannel::blocks(&OutboundMessage::text("just information"));
        assert!(blocks.iter().all(|b| b["type"] != "actions"));
    }
}
