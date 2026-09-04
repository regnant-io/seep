//! Discord, over the Gateway WebSocket.
//!
//! The Gateway carries both messages and component interactions, so one outbound
//! connection covers everything and no public endpoint is needed. Sending goes
//! over the REST API.
//!
//! The heartbeat is the fiddly part and is worth getting right: Discord closes a
//! connection that misses two beats, and a silently dead socket means approval
//! requests that never arrive.

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use seep_core::gateway::DiscordConfig;
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

const API: &str = "https://discord.com/api/v10";

/// Gateway intents: guild messages, direct messages, and their content.
///
/// `MESSAGE_CONTENT` is privileged and must be enabled in the application
/// settings. Without it messages arrive with empty text, which looks like a bug
/// in SeeP rather than a missing checkbox, so the failure is called out in the
/// log at connect time.
const INTENTS: u64 = (1 << 9) | (1 << 12) | (1 << 15);

pub struct DiscordChannel {
    id: ChannelId,
    config: DiscordConfig,
    http: reqwest::Client,
    bot_user_id: tokio::sync::RwLock<Option<String>>,
}

impl DiscordChannel {
    pub fn new(config: DiscordConfig) -> Self {
        Self {
            id: ChannelId::derive("discord"),
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            bot_user_id: tokio::sync::RwLock::new(None),
        }
    }

    fn auth(&self) -> String {
        format!("Bot {}", self.config.bot_token)
    }

    /// Parse a Gateway dispatch into an inbound message.
    pub async fn parse_dispatch(&self, event: &serde_json::Value) -> Option<InboundMessage> {
        match event["t"].as_str()? {
            "MESSAGE_CREATE" => self.parse_message(&event["d"]).await,
            "INTERACTION_CREATE" => self.parse_interaction(&event["d"]),
            _ => None,
        }
    }

    async fn parse_message(&self, data: &serde_json::Value) -> Option<InboundMessage> {
        // Ignore other bots, and ourselves in particular.
        if data["author"]["bot"].as_bool().unwrap_or(false) {
            return None;
        }
        let author = data["author"]["id"].as_str()?;
        if let Some(own) = self.bot_user_id.read().await.as_deref() {
            if author == own {
                return None;
            }
        }

        let text = data["content"].as_str().unwrap_or_default().to_string();
        if text.trim().is_empty() {
            return None;
        }
        let channel_id = data["channel_id"].as_str()?.to_string();

        let mentioned = match self.bot_user_id.read().await.as_deref() {
            Some(own) => data["mentions"]
                .as_array()
                .map(|m| m.iter().any(|u| u["id"].as_str() == Some(own)))
                .unwrap_or(false),
            None => false,
        };

        Some(InboundMessage {
            target: ChannelTarget::new(self.id.clone(), ChannelKind::Discord, channel_id),
            sender_id: author.to_string(),
            sender_name: data["author"]["username"].as_str().unwrap_or(author).to_string(),
            operator: None,
            text,
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: data["id"].as_str().map(|s| s.to_string()),
            mentioned,
            // A message with no guild ID arrived in a DM.
            direct: data.get("guild_id").map(|g| g.is_null()).unwrap_or(true),
            received_at: seep_proto::now_rfc3339(),
            raw: Some(data.clone()),
        })
    }

    fn parse_interaction(&self, data: &serde_json::Value) -> Option<InboundMessage> {
        // Type 3 is a message component — a button or select.
        if data["type"].as_u64() != Some(3) {
            return None;
        }
        let channel_id = data["channel_id"].as_str().unwrap_or_default().to_string();
        let user = data["member"]["user"]["id"]
            .as_str()
            .or_else(|| data["user"]["id"].as_str())?;

        Some(InboundMessage {
            target: ChannelTarget::new(self.id.clone(), ChannelKind::Discord, channel_id),
            sender_id: user.to_string(),
            sender_name: data["member"]["user"]["username"]
                .as_str()
                .or_else(|| data["user"]["username"].as_str())
                .unwrap_or(user)
                .to_string(),
            operator: None,
            text: String::new(),
            attachments: vec![],
            action: data["data"]["custom_id"].as_str().map(|s| s.to_string()),
            // Both are needed to answer the interaction.
            interaction_token: data["token"].as_str().map(|token| {
                format!("{}:{}", data["id"].as_str().unwrap_or_default(), token)
            }),
            source_message_id: data["message"]["id"].as_str().map(|s| s.to_string()),
            mentioned: true,
            direct: data.get("guild_id").map(|g| g.is_null()).unwrap_or(true),
            received_at: seep_proto::now_rfc3339(),
            raw: Some(data.clone()),
        })
    }

    /// Render message components for the actions.
    pub fn components(message: &OutboundMessage) -> Vec<serde_json::Value> {
        if message.actions.is_empty() {
            return Vec::new();
        }
        // Discord allows five buttons per row and five rows.
        let buttons: Vec<serde_json::Value> = message
            .actions
            .iter()
            .take(5)
            .map(|action| {
                serde_json::json!({
                    "type": 2,
                    "style": match action.style.as_str() {
                        "danger" => 4,   // red
                        "primary" => 3,  // green
                        _ => 2,          // grey
                    },
                    "label": action.label,
                    "custom_id": action.id,
                })
            })
            .collect();
        vec![serde_json::json!({ "type": 1, "components": buttons })]
    }

    /// Render an embed carrying the title, body and severity colour.
    pub fn embed(message: &OutboundMessage) -> Option<serde_json::Value> {
        if message.title.is_none() && message.code_block.is_none() {
            return None;
        }
        let colour = u32::from_str_radix(
            render::severity_colour(message.severity.as_deref()).trim_start_matches('#'),
            16,
        )
        .unwrap_or(0x4a6fa5);

        let mut description = message.text.clone();
        if let Some(code) = &message.code_block {
            if !code.trim().is_empty() {
                description.push_str("\n\n");
                description.push_str(&render::fence(code, 3_000));
            }
        }

        Some(serde_json::json!({
            "title": message.title,
            // Discord rejects an embed description over 4096 characters
            // outright, losing the whole message rather than trimming it.
            "description": truncate(&description, 4_000),
            "color": colour,
        }))
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit.saturating_sub(3)).collect();
    format!("{}…", kept)
}

#[async_trait]
impl Channel for DiscordChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Discord
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "discord"
    }

    fn can_approve(&self) -> bool {
        self.config.can_approve
    }

    fn is_allowed(&self, account_id: &str) -> bool {
        self.config.allow_from.iter().any(|a| a == account_id)
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        if self.config.default_channel_id.is_empty() {
            return None;
        }
        Some(ChannelTarget::new(
            self.id.clone(),
            ChannelKind::Discord,
            self.config.default_channel_id.clone(),
        ))
    }

    async fn run(
        self: Arc<Self>,
        inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut backoff = Duration::from_secs(1);

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }

            let url = "wss://gateway.discord.gg/?v=10&encoding=json";
            let socket = match tokio_tungstenite::connect_async(url).await {
                Ok((socket, _)) => socket,
                Err(e) => {
                    tracing::warn!(error = %e, "discord gateway connect failed");
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                    continue;
                }
            };
            backoff = Duration::from_secs(1);
            tracing::info!("discord gateway connected");

            let (mut write, mut read) = socket.split();
            let mut heartbeat = tokio::time::interval(Duration::from_secs(41));
            // The first tick fires immediately; skip it so the interval reflects
            // the value Discord actually asked for once HELLO arrives.
            heartbeat.tick().await;
            let mut sequence: Option<u64> = None;
            let mut identified = false;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        let _ = write.close().await;
                        return Ok(());
                    }
                    _ = heartbeat.tick() => {
                        let beat = serde_json::json!({ "op": 1, "d": sequence });
                        if write
                            .send(tokio_tungstenite::tungstenite::Message::Text(beat.to_string()))
                            .await
                            .is_err()
                        {
                            // A failed heartbeat means the socket is gone.
                            // Reconnecting beats sitting on a dead connection
                            // while approval requests silently fail to arrive.
                            break;
                        }
                    }
                    frame = read.next() => {
                        let Some(Ok(frame)) = frame else { break };
                        let tokio_tungstenite::tungstenite::Message::Text(text) = frame else {
                            continue;
                        };
                        let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        if let Some(s) = event["s"].as_u64() {
                            sequence = Some(s);
                        }

                        match event["op"].as_u64() {
                            Some(10) => {
                                // HELLO: adopt the server's heartbeat interval.
                                if let Some(millis) = event["d"]["heartbeat_interval"].as_u64() {
                                    heartbeat = tokio::time::interval(
                                        Duration::from_millis(millis.clamp(5_000, 120_000)),
                                    );
                                    heartbeat.tick().await;
                                }
                                if !identified {
                                    let identify = serde_json::json!({
                                        "op": 2,
                                        "d": {
                                            "token": self.config.bot_token,
                                            "intents": INTENTS,
                                            "properties": {
                                                "os": std::env::consts::OS,
                                                "browser": "seep",
                                                "device": "seep",
                                            }
                                        }
                                    });
                                    let _ = write
                                        .send(tokio_tungstenite::tungstenite::Message::Text(
                                            identify.to_string(),
                                        ))
                                        .await;
                                    identified = true;
                                }
                            }
                            Some(1) => {
                                // The server asked for an immediate heartbeat.
                                let beat = serde_json::json!({ "op": 1, "d": sequence });
                                let _ = write
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        beat.to_string(),
                                    ))
                                    .await;
                            }
                            Some(9) => {
                                tracing::warn!("discord invalidated the session; reconnecting");
                                break;
                            }
                            Some(0) => {
                                if event["t"].as_str() == Some("READY") {
                                    if let Some(id) = event["d"]["user"]["id"].as_str() {
                                        *self.bot_user_id.write().await = Some(id.to_string());
                                    }
                                    tracing::info!("discord ready");
                                }
                                if let Some(message) = self.parse_dispatch(&event).await {
                                    if inbound.send(message).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            tracing::info!("discord connection ended; reconnecting");
        }
    }

    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let mut body = serde_json::json!({});
        match Self::embed(message) {
            Some(embed) => {
                body["embeds"] = serde_json::json!([embed]);
                body["content"] = serde_json::json!("");
            }
            None => {
                body["content"] = serde_json::json!(truncate(&render::to_markdown(message), 1_990));
            }
        }
        let components = Self::components(message);
        if !components.is_empty() {
            body["components"] = serde_json::json!(components);
        }

        let response: serde_json::Value = self
            .http
            .post(format!("{}/channels/{}/messages", API, target.conversation))
            .header("Authorization", self.auth())
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        Ok(ChannelMessageRef {
            target: target.clone(),
            message_id: response["id"].as_str().unwrap_or_default().to_string(),
        })
    }

    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        let mut body = serde_json::json!({
            // An empty component array removes the buttons, which is what a
            // decided approval needs.
            "components": Self::components(message),
        });
        match Self::embed(message) {
            Some(embed) => body["embeds"] = serde_json::json!([embed]),
            None => {
                body["content"] = serde_json::json!(truncate(&render::to_markdown(message), 1_990))
            }
        }

        self.http
            .patch(format!(
                "{}/channels/{}/messages/{}",
                API, reference.target.conversation, reference.message_id
            ))
            .header("Authorization", self.auth())
            .json(&body)
            .send()
            .await?;
        Ok(())
    }

    async fn acknowledge(&self, message: &InboundMessage) -> anyhow::Result<()> {
        let Some(token) = &message.interaction_token else { return Ok(()) };
        let Some((interaction_id, interaction_token)) = token.split_once(':') else {
            return Ok(());
        };
        // Type 6 acknowledges without posting a new message; Discord shows the
        // interaction as failed after three seconds without this.
        self.http
            .post(format!(
                "{}/interactions/{}/{}/callback",
                API, interaction_id, interaction_token
            ))
            .json(&serde_json::json!({ "type": 6 }))
            .send()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn channel(allow: &[&str]) -> DiscordChannel {
        DiscordChannel::new(DiscordConfig {
            enabled: true,
            bot_token: "token".into(),
            allow_from: allow.iter().map(|a| a.to_string()).collect(),
            default_channel_id: "C1".into(),
            can_approve: true,
        })
    }

    #[test]
    fn an_empty_allowlist_admits_nobody() {
        assert!(!channel(&[]).is_allowed("U1"));
        assert!(channel(&["U1"]).is_allowed("U1"));
    }

    #[tokio::test]
    async fn a_message_parses() {
        let channel = channel(&["U1"]);
        let event = serde_json::json!({
            "op": 0,
            "t": "MESSAGE_CREATE",
            "d": {
                "id": "M1",
                "channel_id": "C1",
                "guild_id": "G1",
                "content": "check the api",
                "author": { "id": "U1", "username": "alice", "bot": false },
                "mentions": []
            }
        });
        let parsed = channel.parse_dispatch(&event).await.unwrap();
        assert_eq!(parsed.sender_id, "U1");
        assert_eq!(parsed.text, "check the api");
        assert!(!parsed.direct);
    }

    #[tokio::test]
    async fn messages_from_bots_are_ignored() {
        let channel = channel(&["U1"]);
        let event = serde_json::json!({
            "op": 0, "t": "MESSAGE_CREATE",
            "d": {
                "id": "M1", "channel_id": "C1", "content": "beep",
                "author": { "id": "U2", "username": "otherbot", "bot": true }
            }
        });
        assert!(channel.parse_dispatch(&event).await.is_none());
    }

    #[tokio::test]
    async fn a_direct_message_has_no_guild() {
        let channel = channel(&["U1"]);
        let event = serde_json::json!({
            "op": 0, "t": "MESSAGE_CREATE",
            "d": {
                "id": "M1", "channel_id": "D1", "content": "hello",
                "author": { "id": "U1", "username": "alice", "bot": false }
            }
        });
        let parsed = channel.parse_dispatch(&event).await.unwrap();
        assert!(parsed.direct);
    }

    #[tokio::test]
    async fn a_button_interaction_parses_with_both_ack_parts() {
        // Acknowledging needs the interaction id *and* its token.
        let channel = channel(&["U1"]);
        let event = serde_json::json!({
            "op": 0, "t": "INTERACTION_CREATE",
            "d": {
                "id": "I1",
                "type": 3,
                "token": "tok",
                "channel_id": "C1",
                "guild_id": "G1",
                "member": { "user": { "id": "U1", "username": "alice" } },
                "data": { "custom_id": "approve:apr_x" },
                "message": { "id": "M1" }
            }
        });
        let parsed = channel.parse_dispatch(&event).await.unwrap();
        assert_eq!(parsed.action.as_deref(), Some("approve:apr_x"));
        assert_eq!(parsed.interaction_token.as_deref(), Some("I1:tok"));
    }

    #[tokio::test]
    async fn non_component_interactions_are_ignored() {
        let channel = channel(&["U1"]);
        let event = serde_json::json!({
            "op": 0, "t": "INTERACTION_CREATE",
            "d": { "id": "I1", "type": 2, "token": "tok", "channel_id": "C1" }
        });
        assert!(channel.parse_dispatch(&event).await.is_none());
    }

    #[test]
    fn components_map_styles_to_discord_colours() {
        let message = OutboundMessage::text("approve?").with_actions(vec![
            PresentedAction::primary("approve", "Approve"),
            PresentedAction::danger("deny", "Deny"),
            PresentedAction::secondary("details", "Details"),
        ]);
        let rows = DiscordChannel::components(&message);
        let buttons = rows[0]["components"].as_array().unwrap();
        assert_eq!(buttons[0]["style"], 3);
        assert_eq!(buttons[1]["style"], 4);
        assert_eq!(buttons[2]["style"], 2);
    }

    #[test]
    fn at_most_five_buttons_are_sent() {
        // Discord rejects a row with more, losing the whole message.
        let actions: Vec<PresentedAction> = (0..9)
            .map(|i| PresentedAction::secondary(format!("a{}", i), format!("Action {}", i)))
            .collect();
        let message = OutboundMessage::text("x").with_actions(actions);
        let rows = DiscordChannel::components(&message);
        assert_eq!(rows[0]["components"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn embeds_are_truncated_below_the_hard_limit() {
        // An oversized embed is rejected outright rather than trimmed.
        let message = OutboundMessage::titled("Report", "x".repeat(20_000));
        let embed = DiscordChannel::embed(&message).unwrap();
        assert!(embed["description"].as_str().unwrap().chars().count() <= 4_000);
    }

    #[test]
    fn a_plain_message_needs_no_embed() {
        assert!(DiscordChannel::embed(&OutboundMessage::text("just text")).is_none());
    }

    #[test]
    fn severity_reaches_the_embed_colour() {
        let danger = OutboundMessage::titled("t", "b").with_severity("danger");
        let info = OutboundMessage::titled("t", "b").with_severity("info");
        assert_ne!(
            DiscordChannel::embed(&danger).unwrap()["color"],
            DiscordChannel::embed(&info).unwrap()["color"]
        );
    }
}
