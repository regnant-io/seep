//! # seep-channels
//!
//! Five messaging platforms behind one interface.
//!
//! The gateway never knows which platform a message came from. It receives
//! [`seep_proto::InboundMessage`] and sends [`seep_proto::OutboundMessage`]; each
//! adapter translates. Adding a sixth platform means writing one file, not
//! touching the approval engine.
//!
//! Two rules are enforced in every adapter and tested for each:
//!
//! * **An unrecognised sender is a stranger.** Their message is data the operator
//!   may want to see, never an instruction, and never an approval. Allowlists
//!   default to empty, and empty means nobody.
//! * **A channel that can notify is not automatically a channel that can
//!   authorize.** A public status channel should be able to receive an incident
//!   report without becoming a place where anyone can approve a production change.

pub mod discord;
pub mod manager;
pub mod render;
pub mod slack;
pub mod telegram;
pub mod terminal;
pub mod web;
pub mod whatsapp;

use async_trait::async_trait;
use seep_proto::channel::{
    ChannelDescriptor, ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage,
    OutboundMessage,
};
use seep_proto::ids::ChannelId;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub use manager::ChannelManager;

/// One messaging integration.
#[async_trait]
pub trait Channel: Send + Sync {
    fn kind(&self) -> ChannelKind;
    fn id(&self) -> ChannelId;
    fn name(&self) -> &str;

    /// Whether this channel may carry approvals, as opposed to only notifications.
    fn can_approve(&self) -> bool;

    /// Whether a platform account is permitted to interact at all.
    ///
    /// Returning `false` does not mean "ignore silently" — the manager records
    /// the attempt so an operator can see that someone tried.
    fn is_allowed(&self, account_id: &str) -> bool;

    /// Where unsolicited notifications go.
    fn default_target(&self) -> Option<ChannelTarget>;

    /// Run the receive loop until cancelled. Channels that receive by webhook
    /// instead return immediately.
    async fn run(
        self: std::sync::Arc<Self>,
        inbound: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()>;

    /// Deliver a message.
    async fn send(
        &self,
        target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef>;

    /// Rewrite a message in place, so a decided approval stops showing live buttons.
    async fn update(
        &self,
        reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()>;

    /// Acknowledge an interaction so the platform stops showing a spinner.
    async fn acknowledge(&self, _message: &InboundMessage) -> anyhow::Result<()> {
        Ok(())
    }

    /// Handle an inbound webhook, for platforms that deliver that way.
    async fn handle_webhook(
        &self,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> anyhow::Result<Vec<InboundMessage>> {
        Ok(Vec::new())
    }

    /// Answer a platform's webhook verification challenge, if it has one.
    fn verify_challenge(&self, _query: &[(String, String)]) -> Option<String> {
        None
    }

    fn descriptor(&self) -> ChannelDescriptor {
        ChannelDescriptor {
            id: self.id(),
            kind: self.kind(),
            name: self.name().to_string(),
            enabled: true,
            can_approve: self.can_approve(),
            default_target: self.default_target(),
            connected: false,
            last_error: None,
        }
    }
}

/// Constant-time comparison, for signatures and shared secrets.
///
/// A normal `==` on a secret leaks its prefix through timing. That is a
/// theoretical concern for most comparisons and a real one for a webhook
/// signature an attacker can submit repeatedly.
pub fn secure_equals(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// HMAC-SHA256, used by several platforms to sign webhook payloads.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_comparison_matches_equal_values() {
        assert!(secure_equals(b"abc123", b"abc123"));
        assert!(!secure_equals(b"abc123", b"abc124"));
    }

    #[test]
    fn secure_comparison_rejects_different_lengths() {
        assert!(!secure_equals(b"abc", b"abcd"));
        assert!(secure_equals(b"", b""));
    }

    #[test]
    fn hmac_matches_a_known_vector() {
        // RFC 4231 test case 1.
        let key = [0x0b; 20];
        let digest = hmac_sha256_hex(&key, b"Hi There");
        assert_eq!(
            digest,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_changes_with_the_key() {
        assert_ne!(
            hmac_sha256_hex(b"key-one", b"payload"),
            hmac_sha256_hex(b"key-two", b"payload")
        );
    }
}
