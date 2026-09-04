//! Fleet node description: what a machine is, what it can do, and how it's doing.

use crate::ids::NodeId;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Which environment a node belongs to. This is the single most important label
/// in the system: policy keys off it, and a mistake here is the difference
/// between restarting a dev container and restarting production.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeEnv {
    Dev,
    Staging,
    Prod,
    /// Explicitly unclassified. Treated as strictly as `Prod` by default policy,
    /// because an unlabelled machine is more likely to be an unreviewed
    /// production box than a scratch VM.
    #[default]
    Unknown,
}

impl NodeEnv {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeEnv::Dev => "dev",
            NodeEnv::Staging => "staging",
            NodeEnv::Prod => "prod",
            NodeEnv::Unknown => "unknown",
        }
    }

    /// Parse from a free-form label value, tolerating the many spellings that
    /// appear in real infrastructure inventories.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "dev" | "development" | "local" | "sandbox" => NodeEnv::Dev,
            "staging" | "stage" | "stg" | "qa" | "test" | "uat" | "preprod" | "pre-prod" => {
                NodeEnv::Staging
            }
            "prod" | "production" | "live" => NodeEnv::Prod,
            _ => NodeEnv::Unknown,
        }
    }

    /// Whether this environment should be treated with production-grade caution.
    pub fn is_sensitive(&self) -> bool {
        matches!(self, NodeEnv::Prod | NodeEnv::Unknown)
    }
}

impl std::fmt::Display for NodeEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Connected and heartbeating within the expected interval.
    Online,
    /// Connected but missing heartbeats, or reporting resource pressure.
    Degraded,
    /// No live connection.
    Offline,
    /// Enrolled but explicitly paused by an operator; receives no work.
    Quarantined,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Online => "online",
            NodeStatus::Degraded => "degraded",
            NodeStatus::Offline => "offline",
            NodeStatus::Quarantined => "quarantined",
        }
    }

    /// Whether the gateway may dispatch work here.
    pub fn accepts_work(&self) -> bool {
        matches!(self, NodeStatus::Online | NodeStatus::Degraded)
    }
}

/// A tool a node advertises. The gateway never assumes a node can do something —
/// it only dispatches tools the node itself claimed at handshake time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments.
    pub input_schema: serde_json::Value,
    /// Worst-case blast radius this tool can produce, as declared by its provider.
    /// Policy may raise it based on arguments, but never lowers it.
    pub max_blast_radius: String,
    /// Whether an executed call can be undone via a snapshot.
    #[serde(default)]
    pub reversible: bool,
    /// Whether the tool only observes and never mutates. Read-only tools are what
    /// the agent is allowed to use during autonomous incident triage.
    #[serde(default)]
    pub read_only: bool,
    /// Provider that supplies this tool: `builtin`, `mcp:<server>`, `skill:<name>`.
    #[serde(default)]
    pub provider: String,
}

impl ToolSpec {
    pub fn builtin(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: serde_json::Value,
        max_blast_radius: &str,
        read_only: bool,
        reversible: bool,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            max_blast_radius: max_blast_radius.to_string(),
            reversible,
            read_only,
            provider: "builtin".into(),
        }
    }
}

/// What a node reports it can do, gathered at connection time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub tools: Vec<ToolSpec>,
    /// Detected facts about the host: `docker`, `kubectl`, `systemd`, `git`, …
    #[serde(default)]
    pub features: Vec<String>,
    /// Maximum concurrent steps this node will accept.
    #[serde(default = "default_concurrency")]
    pub max_concurrency: u32,
}

fn default_concurrency() -> u32 {
    4
}

impl NodeCapabilities {
    pub fn tool(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|t| t.name == name)
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// A point-in-time resource sample from a node. Kept deliberately small: this
/// arrives every few seconds from every machine, so it must stay cheap to ship,
/// store, and render.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_avg_1m: f32,
    pub uptime_secs: u64,
    pub process_count: u32,
    /// Steps currently executing on this node.
    #[serde(default)]
    pub active_steps: u32,
    pub sampled_at: String,
}

impl NodeMetrics {
    pub fn memory_percent(&self) -> f32 {
        if self.memory_total_bytes == 0 {
            return 0.0;
        }
        (self.memory_used_bytes as f64 / self.memory_total_bytes as f64 * 100.0) as f32
    }

    pub fn disk_percent(&self) -> f32 {
        if self.disk_total_bytes == 0 {
            return 0.0;
        }
        (self.disk_used_bytes as f64 / self.disk_total_bytes as f64 * 100.0) as f32
    }

    /// Whether these numbers warrant marking the node degraded.
    pub fn indicates_pressure(&self) -> bool {
        self.cpu_percent > 95.0 || self.memory_percent() > 95.0 || self.disk_percent() > 95.0
    }
}

/// Everything the gateway knows about one machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    /// Operator-facing name. Defaults to the hostname, but is editable, because
    /// `ip-10-0-4-221` is not a useful thing to read in an alert at 3am.
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
    /// Base64 ed25519 public key. Pinned at enrollment; a node presenting a
    /// different key is rejected rather than silently re-enrolled.
    pub public_key: String,
    #[serde(default)]
    pub labels: IndexMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub env: NodeEnv,
    pub status: NodeStatus,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    pub capabilities: NodeCapabilities,
    #[serde(default)]
    pub metrics: Option<NodeMetrics>,
    /// Free-form operator note, shown wherever the node is displayed.
    #[serde(default)]
    pub note: Option<String>,
}

impl NodeInfo {
    /// Whether the node has heartbeated recently enough to be considered live.
    pub fn is_live(&self, stale_after_secs: i64) -> bool {
        match self.last_seen {
            Some(seen) => (Utc::now() - seen).num_seconds() < stale_after_secs,
            None => false,
        }
    }

    /// Seconds since the last heartbeat, or `None` if never seen.
    pub fn seconds_since_seen(&self) -> Option<i64> {
        self.last_seen.map(|s| (Utc::now() - s).num_seconds())
    }

    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(|s| s.as_str())
    }

    /// A compact one-line description for chat and CLI output.
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) · {} · {} · {}",
            self.name,
            self.id.short(),
            self.env,
            self.status.as_str(),
            self.os
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing_tolerates_real_world_spellings() {
        assert_eq!(NodeEnv::parse("PRODUCTION"), NodeEnv::Prod);
        assert_eq!(NodeEnv::parse(" stg "), NodeEnv::Staging);
        assert_eq!(NodeEnv::parse("development"), NodeEnv::Dev);
        assert_eq!(NodeEnv::parse("weird"), NodeEnv::Unknown);
    }

    #[test]
    fn unknown_env_is_treated_as_sensitive() {
        // An unlabelled machine must not be the easy path to a prod outage.
        assert!(NodeEnv::Unknown.is_sensitive());
        assert!(NodeEnv::Prod.is_sensitive());
        assert!(!NodeEnv::Dev.is_sensitive());
    }

    #[test]
    fn metrics_percentages_handle_zero_totals() {
        let m = NodeMetrics::default();
        assert_eq!(m.memory_percent(), 0.0);
        assert_eq!(m.disk_percent(), 0.0);
        assert!(!m.indicates_pressure());
    }

    #[test]
    fn quarantined_nodes_receive_no_work() {
        assert!(!NodeStatus::Quarantined.accepts_work());
        assert!(!NodeStatus::Offline.accepts_work());
        assert!(NodeStatus::Degraded.accepts_work());
    }
}
