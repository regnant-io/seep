//! Node identity and enrollment.
//!
//! A node's identity is a keypair it generates itself and never transmits. What
//! goes to the gateway is the public half, once, during enrollment — after which
//! the gateway pins it, and a node presenting a different key is refused rather
//! than silently re-enrolled.
//!
//! The environment label (`prod`, `staging`) comes back *from* the gateway,
//! stamped into the enrollment token by whoever issued it. A node cannot declare
//! its own environment, because a machine that could call itself `dev` could walk
//! past every production policy.

use seep_identity::keys::{KeyPair, KeyRole};
use seep_proto::ids::NodeId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What a node knows about itself and its gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: NodeId,
    /// The gateway's URL, e.g. `wss://ops.example.com`.
    pub gateway_url: String,
    /// The gateway's public key, pinned at enrollment. Every approval bundle is
    /// checked against this; a bundle sealed by anything else is refused.
    pub gateway_public_key: String,
    /// Assigned by the gateway from the enrollment token.
    pub env: String,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub name: String,
}

impl NodeIdentity {
    /// Where a node keeps its state.
    pub fn default_dir() -> PathBuf {
        seep_core::config::Config::seep_home().join("node")
    }

    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join("identity.json")
    }

    pub fn key_path_in(dir: &Path) -> PathBuf {
        dir.join("node.key")
    }

    pub fn nonce_path_in(dir: &Path) -> PathBuf {
        dir.join("nonces.log")
    }

    pub fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = Self::path_in(dir);
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(text.trim_start_matches('\u{feff}'))?))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path_in(dir);
        // Write-then-rename: an interrupted save must not leave a node unable to
        // identify itself and therefore unable to reconnect.
        let temp = path.with_extension("writing");
        std::fs::write(&temp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    /// The WebSocket URL for the node connection.
    pub fn socket_url(&self) -> String {
        let base = self.gateway_url.trim_end_matches('/');
        let base = base
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{}/ws/node", base)
    }

    /// The HTTP base, for enrollment and health checks.
    pub fn http_url(&self) -> String {
        let base = self.gateway_url.trim_end_matches('/');
        base.replacen("wss://", "https://", 1)
            .replacen("ws://", "http://", 1)
    }
}

/// Load an existing node key, or create one.
pub fn load_or_create_key(dir: &Path, name: &str) -> anyhow::Result<KeyPair> {
    std::fs::create_dir_all(dir)?;
    Ok(KeyPair::load_or_create(
        &NodeIdentity::key_path_in(dir),
        KeyRole::Node,
        name,
        None,
    )?)
}

/// Enroll this machine with a gateway.
///
/// Generates a keypair if one does not exist, presents the token, and stores what
/// comes back. Idempotent in the sense that re-running with a fresh token
/// re-enrolls the same key; the key itself is never regenerated once created,
/// because that would orphan the gateway's pin.
pub async fn enroll(
    dir: &Path,
    gateway_url: &str,
    token: &str,
) -> anyhow::Result<NodeIdentity> {
    let hostname = seep_core::platform::hostname();
    let key = load_or_create_key(dir, &hostname)?;

    let http_base = gateway_url
        .trim_end_matches('/')
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client
        .post(format!("{}/api/v1/enroll", http_base))
        .json(&serde_json::json!({
            "token": token,
            "public_key": key.public_key().0,
            "hostname": hostname,
            "os": seep_core::platform::os_name(),
            "arch": std::env::consts::ARCH,
            "agent_version": env!("CARGO_PKG_VERSION"),
        }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("could not reach the gateway at {}: {}", http_base, e))?;

    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);

    if !status.is_success() {
        anyhow::bail!(
            "enrollment refused ({}): {}",
            status.as_u16(),
            body["error"].as_str().unwrap_or("no reason given")
        );
    }

    let identity = NodeIdentity {
        node_id: NodeId::parse(
            body["node_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("the gateway did not return a node id"))?,
        ),
        gateway_url: gateway_url.trim_end_matches('/').to_string(),
        gateway_public_key: body["gateway_public_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("the gateway did not return its public key"))?
            .to_string(),
        // Assigned by the gateway, never self-declared.
        env: body["env"].as_str().unwrap_or("unknown").to_string(),
        enrolled_at: chrono::Utc::now(),
        name: hostname,
    };
    identity.save(dir)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn identity(url: &str) -> NodeIdentity {
        NodeIdentity {
            node_id: NodeId::derive("web-01"),
            gateway_url: url.into(),
            gateway_public_key: "gw-key".into(),
            env: "prod".into(),
            enrolled_at: chrono::Utc::now(),
            name: "web-01".into(),
        }
    }

    #[test]
    fn identity_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let original = identity("https://ops.example.com");
        original.save(dir.path()).unwrap();

        let loaded = NodeIdentity::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.node_id, original.node_id);
        assert_eq!(loaded.gateway_public_key, "gw-key");
        assert_eq!(loaded.env, "prod");
    }

    #[test]
    fn a_missing_identity_is_not_an_error() {
        let dir = tempdir().unwrap();
        assert!(NodeIdentity::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn socket_urls_upgrade_the_scheme() {
        assert_eq!(
            identity("https://ops.example.com").socket_url(),
            "wss://ops.example.com/ws/node"
        );
        assert_eq!(
            identity("http://localhost:7878").socket_url(),
            "ws://localhost:7878/ws/node"
        );
        assert_eq!(
            identity("wss://ops.example.com/").socket_url(),
            "wss://ops.example.com/ws/node"
        );
    }

    #[test]
    fn http_urls_downgrade_the_scheme() {
        assert_eq!(
            identity("wss://ops.example.com").http_url(),
            "https://ops.example.com"
        );
        assert_eq!(identity("ws://localhost:7878").http_url(), "http://localhost:7878");
    }

    #[test]
    fn a_node_key_is_created_once_and_then_reused() {
        // Regenerating would orphan the gateway's pin and lock the node out.
        let dir = tempdir().unwrap();
        let first = load_or_create_key(dir.path(), "web-01").unwrap();
        let second = load_or_create_key(dir.path(), "web-01").unwrap();
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn the_private_key_never_appears_in_the_identity_file() {
        let dir = tempdir().unwrap();
        let key = load_or_create_key(dir.path(), "web-01").unwrap();
        identity("https://ops.example.com").save(dir.path()).unwrap();

        let contents = std::fs::read_to_string(NodeIdentity::path_in(dir.path())).unwrap();
        assert!(!contents.contains(&key.public_key().0), "not even the public key belongs here");
        assert!(!contents.contains("secret"));
    }

    #[tokio::test]
    async fn enrollment_against_an_unreachable_gateway_says_so_plainly() {
        let dir = tempdir().unwrap();
        let error = enroll(dir.path(), "http://127.0.0.1:1", "seep_enroll_x")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("could not reach the gateway"));
    }
}
