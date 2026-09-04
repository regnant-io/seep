//! WhatsApp, via the Business Cloud API.
//!
//! The one adapter that genuinely needs a public URL: Meta delivers messages by
//! webhook and offers no outbound-connection option. The gateway routes those
//! POSTs here.
//!
//! Because the endpoint is public, signature verification is not optional. Every
//! payload carries an `X-Hub-Signature-256` HMAC over the raw body, and an
//! unsigned or mis-signed request is discarded before it is parsed — an
//! unauthenticated path that can inject messages into an ops agent would be a
//! remote-control interface for anyone who found the URL.

use async_trait::async_trait;
use seep_core::gateway::WhatsAppConfig;
use seep_proto::channel::{
    ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage, OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{hmac_sha256_hex, render, secure_equals, Channel};

const API: &str = "https://graph.facebook.com/v21.0";

pub struct WhatsAppChannel {
    id: ChannelId,
    config: WhatsAppConfig,
    http: reqwest::Client,
}

impl WhatsAppChannel {
    pub fn new(config: WhatsAppConfig) -> Self {
        Self {
            id: ChannelId::derive("whatsapp"),
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Verify the `X-Hub-Signature-256` header against the raw body.
    ///
    /// Returns `false` when no app secret is configured. Accepting unsigned
    /// requests because verification "is not set up yet" is how a public webhook
    /// becomes an open command channel.
    pub fn verify_signature(&self, headers: &[(String, String)], body: &[u8]) -> bool {
        if self.config.app_secret.is_empty() {
            tracing::error!(
                "whatsapp app_secret is not configured; refusing to trust webhook payloads"
            );
            return false;
        }
        let Some(provided) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-hub-signature-256"))
            .map(|(_, value)| value.trim())
        else {
            return false;
        };
        let Some(provided) = provided.strip_prefix("sha256=") else {
            return false;
        };
        let expected = hmac_sha256_hex(self.config.app_secret.as_bytes(), body);
        secure_equals(provided.as_bytes(), expected.as_bytes())
    }

    /// Parse a verified webhook payload into inbound messages.
    pub fn parse_payload(&self, payload: &serde_json::Value) -> Vec<InboundMessage> {
        let mut out = Vec::new();
        let Some(entries) = payload["entry"].as_array() else { return out };

        for entry in entries {
            let Some(changes) = entry["changes"].as_array() else { continue };
            for change in changes {
                let value = &change["value"];
                let Some(messages) = value["messages"].as_array() else { continue };
                // Meta sends the display name separately from the message.
                let profile_name = value["contacts"][0]["profile"]["name"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();

                for message in messages {
                    if let Some(parsed) = self.parse_message(message, &profile_name) {
                        out.push(parsed);
                    }
                }
            }
        }
        out
    }

    fn parse_message(
        &self,
        message: &serde_json::Value,
        profile_name: &str,
    ) -> Option<InboundMessage> {
        let from = message["from"].as_str()?.to_string();
        let message_id = message["id"].as_str().map(|s| s.to_string());

        let (text, action) = match message["type"].as_str()? {
            "text" => (message["text"]["body"].as_str()?.to_string(), None),
            "interactive" => {
                let reply = &message["interactive"]["button_reply"];
                let id = reply["id"].as_str()?.to_string();
                (reply["title"].as_str().unwrap_or_default().to_string(), Some(id))
            }
            "button" => {
                let payload = message["button"]["payload"].as_str()?.to_string();
                (message["button"]["text"].as_str().unwrap_or_default().to_string(), Some(payload))
            }
            // Media, reactions, and status updates are not something the agent
            // acts on; ignoring them quietly is correct.
            _ => return None,
        };

        if text.trim().is_empty() && action.is_none() {
            return None;
        }

        Some(InboundMessage {
            // On WhatsApp the conversation *is* the phone number.
            target: ChannelTarget::new(self.id.clone(), ChannelKind::WhatsApp, from.clone()),
            sender_id: from,
            sender_name: profile_name.to_string(),
            operator: None,
            text,
            attachments: vec![],
            action,
            interaction_token: None,
            source_message_id: message_id,
            mentioned: true,
            // WhatsApp Cloud API conversations are one-to-one.
            direct: true,
            received_at: seep_proto::now_rfc3339(),
            raw: Some(message.clone()),
        })
    }

    /// Build an interactive-button payload, or fall back to plain text.
    ///
    /// WhatsApp allows at most three buttons of twenty characters each. Exceeding
    /// either is rejected outright, so an approval card that would not fit is
    /// converted into a reply-with-a-word prompt rather than being lost.
    pub fn body_for(&self, to: &str, message: &OutboundMessage) -> serde_json::Value {
        let text = render::to_plain_text(message);

        let usable: Vec<_> = message
            .actions
            .iter()
            .filter(|a| a.label.chars().count() <= 20)
            .take(3)
            .collect();

        if usable.len() == message.actions.len() && !usable.is_empty() {
            return serde_json::json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": to,
                "type": "interactive",
                "interactive": {
                    "type": "button",
                    "body": { "text": clamp(&text, 1_024) },
                    "action": {
                        "buttons": usable.iter().map(|action| serde_json::json!({
                            "type": "reply",
                            "reply": { "id": clamp(&action.id, 256), "title": action.label }
                        })).collect::<Vec<_>>()
                    }
                }
            });
        }

        let mut body = text;
        if !message.actions.is_empty() {
            body.push_str("\n\nReply with one of: ");
            body.push_str(
                &message
                    .actions
                    .iter()
                    .map(|a| a.label.clone())
                    .collect::<Vec<_>>()
                    .join(" / "),
            );
        }
        serde_json::json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": { "preview_url": false, "body": clamp(&body, 4_096) }
        })
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
impl Channel for WhatsAppChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::WhatsApp
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "whatsapp"
    }

    fn can_approve(&self) -> bool {
        self.config.can_approve
    }

    fn is_allowed(&self, account_id: &str) -> bool {
        // Numbers are written inconsistently; compare digits only so
        // "+1 555 0100" and "15550100" are the same person.
        let normalise = |s: &str| s.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
        let candidate = normalise(account_id);
        !candidate.is_empty()
            && self.config.allow_from.iter().any(|a| normalise(a) == candidate)
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        if self.config.default_recipient.is_empty() {
            return None;
        }
        Some(ChannelTarget::new(
            self.id.clone(),
            ChannelKind::WhatsApp,
            self.config.default_recipient.clone(),
        ))
    }

    async fn run(
        self: Arc<Self>,
        _inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Messages arrive by webhook; there is nothing to poll.
        tracing::info!("whatsapp channel ready (webhook-driven)");
        cancel.cancelled().await;
        Ok(())
    }

    async fn handle_webhook(
        &self,
        headers: &[(String, String)],
        body: &[u8],
    ) -> anyhow::Result<Vec<InboundMessage>> {
        if !self.verify_signature(headers, body) {
            anyhow::bail!("whatsapp webhook signature verification failed");
        }
        let payload: serde_json::Value = serde_json::from_slice(body)?;
        Ok(self.parse_payload(&payload))
    }

    fn verify_challenge(&self, query: &[(String, String)]) -> Option<String> {
        let get = |key: &str| {
            query
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        if get("hub.mode") != Some("subscribe") {
            return None;
        }
        let token = get("hub.verify_token")?;
        if self.config.verify_token.is_empty() {
            return None;
        }
        if !secure_equals(token.as_bytes(), self.config.verify_token.as_bytes()) {
            return None;
        }
        get("hub.challenge").map(|c| c.to_string())
    }

    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        let parts = render::split_for(ChannelKind::WhatsApp, message);
        let mut last_id = String::new();

        for part in &parts {
            let response: serde_json::Value = self
                .http
                .post(format!("{}/{}/messages", API, self.config.phone_number_id))
                .bearer_auth(&self.config.access_token)
                .json(&self.body_for(&target.conversation, part))
                .send()
                .await?
                .json()
                .await?;

            if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
                anyhow::bail!(
                    "whatsapp send failed: {}",
                    error["message"].as_str().unwrap_or("unknown error")
                );
            }
            last_id = response["messages"][0]["id"].as_str().unwrap_or_default().to_string();
        }

        Ok(ChannelMessageRef { target: target.clone(), message_id: last_id })
    }

    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        // WhatsApp has no edit API. A follow-up message is the honest fallback:
        // the buttons on the original stay visible, so the replacement states
        // the outcome explicitly rather than relying on the card being updated.
        self.send(&reference.target, message).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn channel(allow: &[&str]) -> WhatsAppChannel {
        WhatsAppChannel::new(WhatsAppConfig {
            enabled: true,
            access_token: "token".into(),
            phone_number_id: "PN1".into(),
            verify_token: "verify-me".into(),
            app_secret: "app-secret".into(),
            allow_from: allow.iter().map(|a| a.to_string()).collect(),
            default_recipient: "15550100".into(),
            can_approve: true,
        })
    }

    fn signed_headers(secret: &str, body: &[u8]) -> Vec<(String, String)> {
        vec![(
            "X-Hub-Signature-256".to_string(),
            format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), body)),
        )]
    }

    #[test]
    fn a_correctly_signed_payload_verifies() {
        let channel = channel(&[]);
        let body = br#"{"entry":[]}"#;
        assert!(channel.verify_signature(&signed_headers("app-secret", body), body));
    }

    #[test]
    fn a_tampered_body_fails_verification() {
        let channel = channel(&[]);
        let headers = signed_headers("app-secret", br#"{"entry":[]}"#);
        assert!(!channel.verify_signature(&headers, br#"{"entry":[{"evil":true}]}"#));
    }

    #[test]
    fn a_signature_from_the_wrong_secret_fails() {
        let channel = channel(&[]);
        let body = br#"{"entry":[]}"#;
        assert!(!channel.verify_signature(&signed_headers("not-the-secret", body), body));
    }

    #[test]
    fn an_unsigned_request_is_refused() {
        let channel = channel(&[]);
        assert!(!channel.verify_signature(&[], b"{}"));
    }

    #[test]
    fn verification_fails_closed_when_no_secret_is_configured() {
        // A public webhook that trusts unsigned payloads is a remote-control
        // interface for anyone who finds the URL.
        let config = WhatsAppConfig { app_secret: String::new(), ..Default::default() };
        let channel = WhatsAppChannel::new(config);
        let body = b"{}";
        assert!(!channel.verify_signature(&signed_headers("", body), body));
    }

    #[tokio::test]
    async fn an_unverified_webhook_is_never_parsed() {
        let channel = channel(&["15550100"]);
        let body = br#"{"entry":[{"changes":[{"value":{"messages":[
            {"from":"15550100","id":"M1","type":"text","text":{"body":"do something"}}]}}]}]}"#;
        assert!(channel.handle_webhook(&[], body).await.is_err());
    }

    #[tokio::test]
    async fn a_verified_webhook_parses_its_messages() {
        let channel = channel(&["15550100"]);
        let body = br#"{"entry":[{"changes":[{"value":{
            "contacts":[{"profile":{"name":"Alice"}}],
            "messages":[{"from":"15550100","id":"M1","type":"text","text":{"body":"is the api up"}}]
        }}]}]}"#;
        let messages = channel
            .handle_webhook(&signed_headers("app-secret", body), body)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "is the api up");
        assert_eq!(messages[0].sender_name, "Alice");
        assert!(messages[0].direct);
    }

    #[test]
    fn a_button_reply_parses_as_an_action() {
        let channel = channel(&["15550100"]);
        let payload = serde_json::json!({
            "entry": [{ "changes": [{ "value": {
                "contacts": [{ "profile": { "name": "Alice" } }],
                "messages": [{
                    "from": "15550100", "id": "M2", "type": "interactive",
                    "interactive": { "button_reply": { "id": "approve:apr_x", "title": "Approve" } }
                }]
            }}]}]
        });
        let messages = channel.parse_payload(&payload);
        assert_eq!(messages[0].action.as_deref(), Some("approve:apr_x"));
    }

    #[test]
    fn media_and_status_messages_are_ignored() {
        let channel = channel(&["15550100"]);
        let payload = serde_json::json!({
            "entry": [{ "changes": [{ "value": {
                "messages": [{ "from": "15550100", "id": "M3", "type": "image", "image": {} }]
            }}]}]
        });
        assert!(channel.parse_payload(&payload).is_empty());
    }

    #[test]
    fn phone_numbers_match_regardless_of_formatting() {
        let channel = channel(&["+1 (555) 010-0"]);
        assert!(channel.is_allowed("15550100"));
        assert!(channel.is_allowed("+1-555-0100"));
        assert!(!channel.is_allowed("15550199"));
        assert!(!channel.is_allowed(""));
    }

    #[test]
    fn an_empty_allowlist_admits_nobody() {
        assert!(!channel(&[]).is_allowed("15550100"));
    }

    #[test]
    fn the_verification_challenge_is_echoed_only_for_the_right_token() {
        let channel = channel(&[]);
        let query = |token: &str| {
            vec![
                ("hub.mode".to_string(), "subscribe".to_string()),
                ("hub.verify_token".to_string(), token.to_string()),
                ("hub.challenge".to_string(), "12345".to_string()),
            ]
        };
        assert_eq!(channel.verify_challenge(&query("verify-me")).as_deref(), Some("12345"));
        assert!(channel.verify_challenge(&query("wrong")).is_none());
        assert!(channel.verify_challenge(&[]).is_none());
    }

    #[test]
    fn short_button_sets_render_as_interactive() {
        let channel = channel(&[]);
        let message = OutboundMessage::text("approve this?").with_actions(vec![
            PresentedAction::primary("approve", "Approve"),
            PresentedAction::danger("deny", "Deny"),
        ]);
        let body = channel.body_for("15550100", &message);
        assert_eq!(body["type"], "interactive");
        assert_eq!(body["interactive"]["action"]["buttons"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn oversized_button_sets_fall_back_to_a_text_prompt() {
        // WhatsApp rejects the message outright rather than trimming, so a card
        // that would not fit becomes a reply-with-a-word prompt.
        let channel = channel(&[]);
        let message = OutboundMessage::text("choose").with_actions(vec![
            PresentedAction::primary("a", "This label is far too long for WhatsApp buttons"),
            PresentedAction::danger("b", "Deny"),
        ]);
        let body = channel.body_for("15550100", &message);
        assert_eq!(body["type"], "text");
        assert!(body["text"]["body"].as_str().unwrap().contains("Reply with one of"));
    }

    #[test]
    fn more_than_three_buttons_falls_back_to_text() {
        let channel = channel(&[]);
        let actions: Vec<PresentedAction> = (0..4)
            .map(|i| PresentedAction::secondary(format!("a{}", i), format!("Opt {}", i)))
            .collect();
        let body = channel.body_for("1", &OutboundMessage::text("x").with_actions(actions));
        assert_eq!(body["type"], "text");
    }
}
